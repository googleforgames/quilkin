package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/cenkalti/backoff"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"quilkin.dev/xds-management-server/pkg/resources"
)

// FileProvider watches a file on disk for resources.
type FileProvider struct {
	configFilePath string
}

// NewFileProvider creates a new FileProvider.
func NewFileProvider(configFilePath string) *FileProvider {
	return &FileProvider{configFilePath: configFilePath}
}

// Run runs the FileProvider.
func (p *FileProvider) Run(ctx context.Context, logger *log.Logger) (<-chan resources.Resources, <-chan error) {
	resourcesCh := make(chan resources.Resources, 100)
	errorCh := make(chan error)

	go runConfigFileProvider(ctx, logger, p.configFilePath, resourcesCh, errorCh)

	return resourcesCh, errorCh
}

func runConfigFileProvider(
	ctx context.Context,
	logger *log.Logger,
	configFilePath string,
	resourcesCh chan<- resources.Resources,
	errorCh chan<- error,
) {
	logger = logger.WithFields(log.Fields{
		"component":   "FileProvider",
		"config_file": configFilePath,
	}).Logger

	defer close(errorCh)

	reloadFileEventCh := make(chan struct{}, 1)
	defer close(reloadFileEventCh)

	// Reads the resource file from disk, parses and send the config to the receiver.
	reloadFile := func() {
		fileBytes, err := ioutil.ReadFile(configFilePath)
		if err != nil {
			log.WithError(err).Warn("failed to read resources config file")
			return
		}

		r := resources.Resources{}
		if err := json.Unmarshal(fileBytes, &r); err != nil {
			log.WithError(err).Warn("failed to JSON unmarshal resources config file")
			return
		}

		resourcesCh <- r
	}

	fileWatcherErrorCh := make(chan error)
	go runConfigFileWatch(
		ctx,
		logger,
		configFilePath,
		reloadFileEventCh,
		fileWatcherErrorCh)

	for {
		select {
		case <-reloadFileEventCh:
			reloadFile()
		case <-ctx.Done():
			logger.Debugf("Exiting: context cancelled")
			return
		case err := <-fileWatcherErrorCh:
			errorCh <- fmt.Errorf("failed to watch config file: %w", err)
			return
		}
	}
}

func runConfigFileWatch(
	ctx context.Context,
	logger *log.Logger,
	configFilePath string,
	reloadFileEventCh chan<- struct{},
	errorCh chan<- error,
) {
	logger = logger.WithFields(log.Fields{"component": "ConfigFileWatcher"}).Logger

	defer close(errorCh)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		errorCh <- fmt.Errorf("failed to create file watcher: %w", err)
		return
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			logger.WithError(err).Warn("failed to close watcher successfully")
		}
	}()

	logger = logger.WithFields(log.Fields{
		"config_file": configFilePath,
	}).Logger

	backOff := backoff.NewExponentialBackOff()
	err = backoff.Retry(func() error {
		if err := watcher.Add(configFilePath); err != nil {
			logger.WithError(err).Warnf("failed to watch file")
			return err
		}
		defer func() {
			if err := watcher.Remove(configFilePath); err != nil {
				logger.WithError(err).Warnf("failed to remove watch")
			}
		}()

		backOff.Reset()

		// Load the initial file contents.
		reloadFileEventCh <- struct{}{}

		for {
			select {
			case <-ctx.Done():
				logger.Debugf("Exiting: context cancelled")
				return nil
			case event, ok := <-watcher.Events:
				if !ok {
					logger.WithError(err).Warn("received watch error event")
					return err
				}

				if event.Op&fsnotify.Remove == fsnotify.Remove {
					return fmt.Errorf("resources file was removed")
				}
				if event.Op&fsnotify.Rename == fsnotify.Rename {
					return fmt.Errorf("resources file was renamed")
				}

				isCreate := event.Op&fsnotify.Create == fsnotify.Create
				isWrite := event.Op&fsnotify.Write == fsnotify.Write
				if !(isCreate || isWrite) {
					continue
				}

				// Write event. We can reload the config file
				reloadFileEventCh <- struct{}{}
			}
		}

	}, backOff)
	if err != nil {
		errorCh <- err
	}
}
