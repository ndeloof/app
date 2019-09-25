package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/docker/cli/cli/streams"
	"github.com/docker/distribution/manifest/schema2"
	"io"
	"os"
	"strings"

	"github.com/opencontainers/go-digest"

	"github.com/containerd/containerd/platforms"
	"github.com/deislabs/cnab-go/bundle"
	"github.com/docker/app/internal/log"
	"github.com/docker/app/types/metadata"
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cnab-to-oci/remotes"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/registry"
	"github.com/morikuni/aec"
	ocischemav1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const ( // Docker specific annotations and values
	// DockerAppFormatAnnotation is the top level annotation specifying the kind of the App Bundle
	DockerAppFormatAnnotation = "io.docker.app.format"
	// DockerAppFormatCNAB is the DockerAppFormatAnnotation value for CNAB
	DockerAppFormatCNAB = "cnab"

	// DockerTypeAnnotation is the annotation that designates the type of the application
	DockerTypeAnnotation = "io.docker.type"
	// DockerTypeApp is the value used to fill DockerTypeAnnotation when targeting a docker-app
	DockerTypeApp = "app"
)

type pushOptions struct {
	platforms    []string
	allPlatforms bool
}

func pushCmd(dockerCli command.Cli) *cobra.Command {
	var opts pushOptions
	cmd := &cobra.Command{
		Use:     "push [APP_TAG] [OPTIONS]",
		Short:   "Push an application to a registry",
		Example: `$ docker app push myrepo/myapp:mytag`,
		Args:    cli.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return checkFlags(cmd.Flags(), opts)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPush(dockerCli, args[0], opts)
		},
	}
	flags := cmd.Flags()
	flags.StringSliceVar(&opts.platforms, "platform", []string{"linux/amd64"}, "For multi-arch service images, push the specified platforms")
	flags.BoolVar(&opts.allPlatforms, "all-platforms", false, "If present, push all platforms")
	return cmd
}

func runPush(dockerCli command.Cli, ref string, opts pushOptions) error {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return err
	}
	named = reference.TagNameOnly(named)
	repo := fmt.Sprintf("%s/%s", reference.Domain(named), reference.Path(named))

	// Get the bundle
	bundleStore, err := prepareBundleStore()
	if err != nil {
		return err
	}

	bndl, err := bundleStore.Read(named)
	if err != nil {
		return err
	}

	// Push the service images
	for service, image := range bndl.Images {
		fmt.Fprintf(dockerCli.Out(), "Pushing service image '%s'\n", service)
		digest, err := push(dockerCli, image.BaseImage, named, opts)
		if err != nil {
			return err
		}
		image.Image = fmt.Sprintf("%s@%s", repo, digest.String())
		image.MediaType = schema2.MediaTypeManifest
		bndl.Images[service] = image
	}

	// Push the invocation images
	for i, image := range bndl.InvocationImages {
		fmt.Fprintf(dockerCli.Out(), "Pushing invocation image\n")
		digest, err := push(dockerCli, image.BaseImage, named, opts)
		if err != nil {
			return err
		}
		image.MediaType = schema2.MediaTypeManifest
		image.Image = fmt.Sprintf("%s@%s", repo, digest.String())
		bndl.InvocationImages[i] = image
	}

	// Push the bundle
	fmt.Fprintf(dockerCli.Out(), "Pushing bundle\n")
	if err = pushBundle(dockerCli, opts, bndl, named); err != nil {
		return err
	}

	if err := persistInBundleStore(named, bndl); err != nil {
		return err
	}

	return nil
}

func push(dockerCli command.Cli, image bundle.BaseImage, named reference.Named, opts pushOptions) (digest.Digest, error) {
	ref := image.Digest
	if ref == "" {
		ref = image.Image
	}
	// FIXME if bundle define image by Addressable Digest (foo@sha256:...), check registry already has it then skip tag&push
	if err := dockerCli.Client().ImageTag(context.Background(), ref, named.String()); err != nil {
		return "", err
	}
	digest, err := pushImage(dockerCli, opts, named)
	if err != nil {
		return "", err
	}
	return digest, nil
}

func pushImage(dockerCli command.Cli, opts pushOptions, ref reference.Named) (digest.Digest, error) {
	logrus.Debugf("Pushing image %q", ref.String())
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return "", err
	}
	encodedAuth, err := command.EncodeAuthToBase64(command.ResolveAuthConfig(context.Background(), dockerCli, repoInfo.Index))
	if err != nil {
		return "", err
	}
	reader, err := dockerCli.Client().ImagePush(context.Background(), ref.String(), types.ImagePushOptions{
		RegistryAuth: encodedAuth,
	})
	if err != nil {
		return "", errors.Wrapf(err, "starting push of %q", ref.String())
	}
	defer reader.Close()
	d := digestCollector{out:dockerCli.Out()}
	if err := jsonmessage.DisplayJSONMessagesToStream(reader, &d, nil); err != nil {
		return "", errors.Wrapf(err, "pushing to %q", ref.String())
	}

	// First attempt : retrieve the registry digest from push stdout
	// FIXME wonder there's a better way, or maybe we could reuse some existing code for this purpose
	dg, err := d.Digest()
	if err == nil && dg != "" {
		return dg, nil
	}

	// Second attempt: query registry for the tag we just pushed
	// FIXME potential race condition
	t, err := dockerCli.RegistryClient(false).GetManifest(context.TODO(), ref)
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve image digest %s", ref.String())
	}
	return t.Descriptor.Digest, nil
}

type digestCollector struct {
	out *streams.Out
	last string
}

// Write implement writer.Write
func (d *digestCollector) Write(p []byte) (n int, err error) {
	d.last = string(p)
	return d.out.Write(p)
}

// Digest return the image digest collected by parsing "docker push" stdout
func (d digestCollector) Digest() (digest.Digest, error) {
	dg := digest.DigestRegexp.FindString(d.last)
	return digest.Parse(dg)
}

// FD implement stream.FD
func (d *digestCollector) FD() uintptr {
	return d.out.FD()
}

// IsTerminal implement stream.IsTerminal
func (d *digestCollector) IsTerminal() bool {
	return d.out.IsTerminal()
}

func pushBundle(dockerCli command.Cli, opts pushOptions, bndl *bundle.Bundle, tag reference.Named) error {
	insecureRegistries, err := insecureRegistriesFromEngine(dockerCli)
	if err != nil {
		return errors.Wrap(err, "could not retrive insecure registries")
	}
	resolver := remotes.CreateResolver(dockerCli.ConfigFile(), insecureRegistries...)
	var display fixupDisplay = &plainDisplay{out: os.Stdout}
	if term.IsTerminal(os.Stdout.Fd()) {
		display = &interactiveDisplay{out: os.Stdout}
	}
	fixupOptions := []remotes.FixupOption{
		remotes.WithEventCallback(display.onEvent),
	}
	if platforms := platformFilter(opts); len(platforms) > 0 {
		fixupOptions = append(fixupOptions, remotes.WithComponentImagePlatforms(platforms))
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		bt, _ := json.MarshalIndent(bndl, "> ", "  ")
		fmt.Println(string(bt))
	}
	// push bundle manifest
	logrus.Debugf("Pushing the bundle %q", tag)
	descriptor, err := remotes.Push(log.WithLogContext(context.Background()), bndl, tag, resolver, true, withAppAnnotations)
	if err != nil {
		return errors.Wrapf(err, "pushing to %q", tag)
	}
	fmt.Fprintf(os.Stdout, "Successfully pushed bundle to %s. Digest is %s.\n", tag.String(), descriptor.Digest)
	return nil
}

func withAppAnnotations(index *ocischemav1.Index) error {
	if index.Annotations == nil {
		index.Annotations = make(map[string]string)
	}
	index.Annotations[DockerAppFormatAnnotation] = DockerAppFormatCNAB
	index.Annotations[DockerTypeAnnotation] = DockerTypeApp
	return nil
}

func platformFilter(opts pushOptions) []string {
	if opts.allPlatforms {
		return nil
	}
	return opts.platforms
}

func retagInvocationImage(dockerCli command.Cli, bndl *bundle.Bundle, newName string) error {
	err := dockerCli.Client().ImageTag(context.Background(), bndl.InvocationImages[0].Image, newName)
	if err != nil {
		return err
	}
	bndl.InvocationImages[0].Image = newName
	return nil
}

type retagResult struct {
	shouldRetag        bool
	cnabRef            reference.Named
	invocationImageRef reference.Named
}

func shouldRetagInvocationImage(meta metadata.AppMetadata, bndl *bundle.Bundle, tagOverride, bundleRef string) (retagResult, error) {
	// Use the bundle reference as a tag override
	if tagOverride == "" && bundleRef != "" {
		tagOverride = bundleRef
	}
	imgName := tagOverride
	var err error
	if imgName == "" {
		imgName, err = makeCNABImageName(meta.Name, meta.Version, "")
		if err != nil {
			return retagResult{}, err
		}
	}
	cnabRef, err := reference.ParseNormalizedNamed(imgName)
	if err != nil {
		return retagResult{}, errors.Wrap(err, imgName)
	}
	if _, digested := cnabRef.(reference.Digested); digested {
		return retagResult{}, errors.Errorf("%s: can't push to a digested reference", cnabRef)
	}
	cnabRef = reference.TagNameOnly(cnabRef)
	expectedInvocationImageRef, err := reference.ParseNormalizedNamed(reference.TagNameOnly(cnabRef).String() + "-invoc")
	if err != nil {
		return retagResult{}, errors.Wrap(err, reference.TagNameOnly(cnabRef).String()+"-invoc")
	}
	currentInvocationImageRef, err := reference.ParseNormalizedNamed(bndl.InvocationImages[0].Image)
	if err != nil {
		return retagResult{}, errors.Wrap(err, bndl.InvocationImages[0].Image)
	}
	return retagResult{
		cnabRef:            cnabRef,
		invocationImageRef: expectedInvocationImageRef,
		shouldRetag:        expectedInvocationImageRef.String() != currentInvocationImageRef.String(),
	}, nil
}

type fixupDisplay interface {
	onEvent(remotes.FixupEvent)
}

type interactiveDisplay struct {
	out               io.Writer
	previousLineCount int
	images            []interactiveImageState
}

func (r *interactiveDisplay) onEvent(ev remotes.FixupEvent) {
	out := bytes.NewBuffer(nil)
	for i := 0; i < r.previousLineCount; i++ {
		fmt.Fprint(out, aec.NewBuilder(aec.Up(1), aec.EraseLine(aec.EraseModes.All)).ANSI)
	}
	switch ev.EventType {
	case remotes.FixupEventTypeCopyImageStart:
		r.images = append(r.images, interactiveImageState{name: ev.SourceImage})
	case remotes.FixupEventTypeCopyImageEnd:
		r.images[r.imageIndex(ev.SourceImage)].done = true
	case remotes.FixupEventTypeProgress:
		r.images[r.imageIndex(ev.SourceImage)].onProgress(ev.Progress)
	}
	r.previousLineCount = 0
	for _, s := range r.images {
		r.previousLineCount += s.print(out)
	}
	r.out.Write(out.Bytes()) //nolint:errcheck // nothing much we can do with an error to write to output.
}

func (r *interactiveDisplay) imageIndex(name string) int {
	for ix, state := range r.images {
		if state.name == name {
			return ix
		}
	}
	return 0
}

type interactiveImageState struct {
	name     string
	progress remotes.ProgressSnapshot
	done     bool
}

func (s *interactiveImageState) onProgress(p remotes.ProgressSnapshot) {
	s.progress = p
}

func (s *interactiveImageState) print(out io.Writer) int {
	if s.done {
		fmt.Fprint(out, aec.Apply(s.name, aec.BlueF))
	} else {
		fmt.Fprint(out, s.name)
	}
	fmt.Fprint(out, "\n")
	lineCount := 1

	for _, p := range s.progress.Roots {
		lineCount += printDescriptorProgress(out, &p, 1)
	}
	return lineCount
}

func printDescriptorProgress(out io.Writer, p *remotes.DescriptorProgressSnapshot, depth int) int {
	fmt.Fprint(out, strings.Repeat(" ", depth))
	name := p.MediaType
	if p.Platform != nil {
		name = platforms.Format(*p.Platform)
	}
	if len(p.Children) == 0 {
		name = fmt.Sprintf("%s...: %s", p.Digest.String()[:15], p.Action)
	}
	doneCount := 0
	for _, c := range p.Children {
		if c.Done {
			doneCount++
		}
	}
	display := name
	if len(p.Children) > 0 {
		display = fmt.Sprintf("%s [%d/%d] (%s...)", name, doneCount, len(p.Children), p.Digest.String()[:15])
	}
	if p.Done {
		display = aec.Apply(display, aec.BlueF)
	}
	if hasError(p) {
		display = aec.Apply(display, aec.RedF)
	}
	fmt.Fprintln(out, display)
	lineCount := 1
	if p.Done {
		return lineCount
	}
	for _, c := range p.Children {
		lineCount += printDescriptorProgress(out, &c, depth+1)
	}
	return lineCount
}

func hasError(p *remotes.DescriptorProgressSnapshot) bool {
	if p.Error != nil {
		return true
	}
	for _, c := range p.Children {
		if hasError(&c) {
			return true
		}
	}
	return false
}

type plainDisplay struct {
	out io.Writer
}

func (r *plainDisplay) onEvent(ev remotes.FixupEvent) {
	switch ev.EventType {
	case remotes.FixupEventTypeCopyImageStart:
		fmt.Fprintf(r.out, "Handling image %s...", ev.SourceImage)
	case remotes.FixupEventTypeCopyImageEnd:
		if ev.Error != nil {
			fmt.Fprintf(r.out, "\nFailure: %s\n", ev.Error)
		} else {
			fmt.Fprint(r.out, " done!\n")
		}
	}
}

func checkFlags(flags *pflag.FlagSet, opts pushOptions) error {
	if opts.allPlatforms && flags.Changed("all-platforms") && flags.Changed("platform") {
		return fmt.Errorf("--all-plaforms and --plaform flags cannot be used at the same time")
	}
	return nil
}
