package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/doctor"
	"github.com/bukansembarangkong/jawaker-panel/internal/version"
)

// agentDoctorTimeout bounds the report, matching the controller's: the
// connectivity probe has its own timeout, and this is the outer ceiling so no
// combination of slow checks can hang the command.
const agentDoctorTimeout = 30 * time.Second

// runDoctor produces a diagnostic report for this node and exits.
//
// It returns an error when a check FAILED, so an installer or a monitoring probe
// can branch on it. A warning does not: an unreachable controller is a warning by
// design, because ARCHITECTURE.md §13 makes a controller outage a non-event on a
// node and treating it as a failure would report a healthy host as broken.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON instead of text")
	stateDir := fs.String("state-dir", defaultStateDir, "state directory")
	skipConnectivity := fs.Bool("skip-connectivity", false, "omit the controller reachability probe")
	connectTimeout := fs.Duration("connect-timeout", 5*time.Second, "how long to wait for the controller")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), agentDoctorTimeout)
	defer cancel()

	report := doctor.Agent(ctx, version.String(), doctor.AgentOptions{
		StateDir:         *stateDir,
		ConnectTimeout:   *connectTimeout,
		SkipConnectivity: *skipConnectivity,
	})

	if *asJSON {
		raw, err := report.JSON()
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
		fmt.Println(string(raw))
	} else {
		fmt.Print(report.Text())
	}

	if !report.Healthy() {
		return errors.New("one or more checks FAILED")
	}
	return nil
}
