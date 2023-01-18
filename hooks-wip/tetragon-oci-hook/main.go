package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// TODO: we might want to contact syslog just to get log rotation
	logfname = "/var/log/tetragon-oci-hook.log"
	// agentAddress = "localhost:54321"
	agentAddress = "unix:///var/run/cilium/tetragon/tetragon.sock"

	uidStringLen = len("00000000-0000-0000-0000-000000000000")
)

var (
	scanFiles = []string{"/bin/ls", "/etc/hostname"}
)

func checkPath(log_ logrus.FieldLogger, path string) {
	log := log_.WithField("path", path)
	log.Info("checking path")

	for _, file := range scanFiles {
		logf := log.WithField("file", file)
		fname := filepath.Join(path, file)
		finfo, err := os.Stat(fname)
		if err != nil {
			logf.WithError(err).Warn("stat failed")
			continue
		}
		stat, ok := finfo.Sys().(*syscall.Stat_t)
		if !ok {
			logf.Warn("not Stat_t")
			continue
		}
		logf.WithField("dev", stat.Dev).WithField("inode", stat.Ino).Info("file found")
	}
}

func readJsonSpec(log logrus.FieldLogger, fname string) (*specs.Spec, error) {
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", fname, err)
	}

	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	return &spec, nil
}

func getTime() string {
	s, _ := time.Now().UTC().MarshalText()
	return string(s)
}

func hookRequest(req *tetragon.RuntimeHookRequest) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, agentAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("connecting to agent (%s) failed: %s", err, agentAddress)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	_, err = client.RuntimeHook(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func createContainerHook(log_ *logrus.Logger) {
	log := log_.WithField("hook", "create-container").WithField("start-time", getTime())

	// rootDir is the current directory
	rootDir, err := os.Getwd()
	var configName string
	if err != nil {
		log.Warn("failed to retrieve CWD: %s", err)
		configName = "./../config.json"
	} else {
		// Use full path for config.json for better log messages
		configName = filepath.Join(rootDir, "..", "config.json")
	}

	// We use the cgroup name to determine the containerID
	// We use the config.json file to get the cgroup name. (We could have used /proc/self/cgroup, but it's more complicated.)
	var containerID, podID string
	spec, err := readJsonSpec(log, configName)
	if err != nil {
		log.WithError(err).Warn("failed to read spec file: %s", configName)
	} else if spec.Linux == nil {
		log.Warn("unexpected error: Linux is empty on spec %+v", spec)
	} else {
		cgPath := spec.Linux.CgroupsPath
		containerID = filepath.Base(cgPath)
		podPath := filepath.Dir(cgPath)
		podID = filepath.Base(podPath)
		if len(podID) > uidStringLen {
			// remove pod prefix
			podID = podID[len(podID)-uidStringLen:]
		}
	}

	if containerID == "" && rootDir == "" {
		log.Warn("unable to determine either RootDir or ContainerID, bailing out")
		return
	}

	req := &tetragon.RuntimeHookRequest{
		Event: &tetragon.RuntimeHookRequest_CreateContainer{
			CreateContainer: &tetragon.CreateContainer{
				PodID:       podID,
				ContainerID: containerID,
				RootDir:     rootDir,
				Annotations: spec.Annotations,
			},
		},
	}

	err = hookRequest(req)
	if err != nil {
		log.WithError(err).WithField("req", req).Warn("hook request to agent failed")
	} else {
		log.WithField("req", req).Info("hook request to agent succeeded")
	}
}

func main() {
	f, err := os.OpenFile(logfname, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	log := logrus.New()
	log.SetOutput(f)

	if len(os.Args) < 2 {
		log.Warn("hook called without arguments, bailing out")
		return
	}

	hookName := os.Args[1]
	switch hookName {
	case "createContainer":
		createContainerHook(log)
	case "createRuntime":
		// do nothing
	default:
		log.WithField("hook", hookName).Warn("hook called with unknown hook")
	}

	return
}