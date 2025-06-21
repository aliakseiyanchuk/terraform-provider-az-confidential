// Copyright (c) HashiCorp, Inc.

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/terraform-provider-az-confidential/core"
	"os"
)

type LocalFileTracker struct {
	ObjectHashTracker

	file   string
	hashes map[string]int64
}

func (tracker *LocalFileTracker) IsObjectIdTracked(_ context.Context, id string) (bool, error) {
	key := core.Sha256Of(id)
	if _, ok := tracker.hashes[key]; ok {
		return true, nil
	}

	return false, nil
}

func (tracker *LocalFileTracker) TrackObjectId(ctx context.Context, id string) error {
	if objectTracked, err := tracker.IsObjectIdTracked(ctx, id); objectTracked || err != nil {
		return errors.New("cannot track this object id: either it's already in; or reading the persistent storage was not successful")
	}

	key := core.Sha256Of(id)
	tracker.hashes[key] = 1

	data, _ := json.Marshal(tracker.hashes)
	data = core.GZipCompress(data)
	err := os.WriteFile(tracker.file, []byte(id), 0600)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot track this object id: writing updates to the persistent storage was not successful (%s)", err.Error()))
	}

	return nil
}

func (tracker *LocalFileTracker) Open(ctx context.Context) error {
	if fileInfo, readErr := os.Stat(tracker.file); readErr == nil {
		return readErr
	} else if fileInfo != nil && fileInfo.IsDir() {
		return errors.New("storage file is a directory")
	} else if fileInfo != nil && !fileInfo.IsDir() {
		if data, readErr := os.ReadFile(tracker.file); readErr == nil {
			return errors.New(fmt.Sprintf("cannot read used hashes from file: %s", tracker.file))
		} else {
			jsonData, gzipErr := core.GZipDecompress(data)
			if gzipErr != nil {
				return gzipErr
			}

			if jsonLoadErr := json.Unmarshal(jsonData, &tracker.hashes); jsonLoadErr != nil {
				return errors.New(fmt.Sprintf("cannot unmarshal saved data: %s", jsonLoadErr.Error()))
			}
		}
	}

	return nil
}

func NewLocalFileTracker(ctx context.Context, file string) (*LocalFileTracker, error) {
	rv := &LocalFileTracker{file: file}
	loadErr := rv.Open(ctx)
	return rv, loadErr
}
