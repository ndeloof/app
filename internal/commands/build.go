package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/buildx/driver"

	"github.com/docker/buildx/util/progress"

	"github.com/docker/app/internal"
	"github.com/docker/buildx/bake"
	"github.com/docker/buildx/build"
	_ "github.com/docker/buildx/driver/docker" // required to get default driver registered, see driver/docker/factory.go:14
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	dockerclient "github.com/docker/docker/client"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type buildOptions struct {
	noCache  bool
	progress string
	pull     bool
	tag      string
}

func buildCmd(dockerCli command.Cli) *cobra.Command {
	var opts buildOptions
	cmd := &cobra.Command{
		Use:     "build [APPLICATION]",
		Short:   "Build service images for the application",
		Example: `$ docker app build myapp.dockerapp`,
		Args:    cli.RequiresRangeArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBuild(dockerCli, args[0], opts)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.noCache, "no-cache", false, "Do not use cache when building the image")
	flags.StringVar(&opts.progress, "progress", "auto", "Set type of progress output (auto, plain, tty). Use plain to show container output")
	flags.BoolVar(&opts.pull, "pull", false, "Always attempt to pull a newer version of the image")
	cmd.Flags().StringVarP(&opts.tag, "tag", "t", "", "Name and optionally a tag in the 'name:tag' format")

	return cmd
}

func runBuild(dockerCli command.Cli, application string, opt buildOptions) error {
	appname := internal.DirNameFromAppName(application)
	f := "./" + appname + "/" + internal.ComposeFileName
	if _, err := os.Stat(f); err != nil {
		if os.IsNotExist(errors.Cause(err)) {
			return fmt.Errorf("no compose file at %s, did you selected the right docker app folder ?", f)
		}
	}

	ctx := appcontext.Context()
	cfg, err := bake.ParseFile(f)
	if err != nil {
		return err
	}
	for k, t := range cfg.Target {
		if strings.HasPrefix(*t.Context, ".") {
			// Relative path in compose file under x.dockerapp refers to parent folder
			// FIXME docker app init should maybe udate them ?
			path, err := filepath.Abs(appname + "/../" + (*t.Context)[1:])
			if err != nil {
				return err
			}
			t.Context = &path
			cfg.Target[k] = t
		}
	}

	buildopts, err := bake.TargetsToBuildOpt(cfg.Target, opt.noCache, opt.pull)
	if err != nil {
		return err
	}

	pw := progress.NewPrinter(ctx, os.Stderr, opt.progress)

	d, err := driver.GetDriver(ctx, "buildx_buildkit_default", nil, dockerCli.Client(), nil, "", nil)
	if err != nil {
		return err
	}
	driverInfo := []build.DriverInfo{
		{
			Name:   "default",
			Driver: d,
		},
	}

	resp, err := build.Build(ctx, driverInfo, buildopts, dockerAPI(dockerCli), dockerCli.ConfigFile(), pw)
	if err != nil {
		return err
	}

	bundle, err := makeBundle(dockerCli, application, nil)
	if err != nil {
		return err
	}

	for k, r := range resp {
		image := bundle.Images[k]
		// FIXME this is dockerd digest, not OCI compliant
		image.Digest = r.ExporterResponse["containerimage.digest"]
		bundle.Images[k] = image
	}

	ref, err := getNamedTagged(opt.tag)
	if err != nil {
		return err
	}

	if err := persistInBundleStore(ref, bundle); err != nil {
		return err
	}

	return nil
}

/// FIXME copy from vendor/github.com/docker/buildx/commands/util.go:318 could probably be made public
func dockerAPI(dockerCli command.Cli) *api {
	return &api{dockerCli: dockerCli}
}

type api struct {
	dockerCli command.Cli
}

func (a *api) DockerAPI(name string) (dockerclient.APIClient, error) {
	if name == "" {
		name = a.dockerCli.CurrentContext()
	}
	return nil, fmt.Errorf("Only support default context in this prototype")
}
