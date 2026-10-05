// Package link finds the project link file and keeps the trusted folder list (PRD 8.5 and 8.6).
package link

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lminii/envs/internal/names"
)

const (
	FileName        = ".envs.json"
	trustedFileName = "trusted.json"
	trustedVersion  = 1
)

var ErrNotFound = errors.New("no link file found")

type linkFile struct {
	Project string `json:"project"`
}

// Find searches from dir upward and returns the first folder that contains a
// link file, with its project name. The search does not go above a folder
// that contains an entry named .git, so a repository inside a linked project
// does not inherit the link.
func Find(dir string) (folder, project string, err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	for {
		path := filepath.Join(dir, FileName)
		data, err := os.ReadFile(path)
		if err == nil {
			project, err := parse(data)
			if err != nil {
				return "", "", fmt.Errorf("invalid link file %s: %w. Run \"envs init\" in that folder to write it again", path, err)
			}
			return dir, project, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return "", "", ErrNotFound
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", ErrNotFound
		}
		dir = parent
	}
}

func parse(data []byte) (string, error) {
	var file linkFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return "", errors.New("the content is not {\"project\":\"<name>\"}")
	}
	if err := names.Project(file.Project); err != nil {
		return "", err
	}
	return file.Project, nil
}

// Write creates the link file in dir.
func Write(dir, project string) error {
	data, err := json.Marshal(linkFile{Project: project})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, FileName), append(data, '\n'), 0o644)
}

type trustedFile struct {
	Version int             `json:"version"`
	Folders []trustedFolder `json:"folders"`
}

type trustedFolder struct {
	Path    string `json:"path"`
	Project string `json:"project"`
}

// Canonical resolves symlinks in folder, so one folder has one form.
func Canonical(folder string) (string, error) {
	abs, err := filepath.Abs(folder)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// IsTrusted reports whether the canonical folder is in the list for project.
// envsDir is the ~/.envs folder.
func IsTrusted(envsDir, canonicalFolder, project string) (bool, error) {
	list, err := loadTrusted(envsDir)
	if err != nil {
		return false, err
	}
	for _, f := range list.Folders {
		if samePath(f.Path, canonicalFolder) && f.Project == project {
			return true, nil
		}
	}
	return false, nil
}

// Trust adds the canonical folder to the list for project. It replaces an
// entry of the same folder for another project.
func Trust(envsDir, canonicalFolder, project string) error {
	list, err := loadTrusted(envsDir)
	if err != nil {
		return err
	}
	folders := []trustedFolder{}
	for _, f := range list.Folders {
		if !samePath(f.Path, canonicalFolder) {
			folders = append(folders, f)
		}
	}
	list.Folders = append(folders, trustedFolder{Path: canonicalFolder, Project: project})
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(envsDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(envsDir, trustedFileName), append(data, '\n'), 0o600)
}

func loadTrusted(envsDir string) (*trustedFile, error) {
	path := filepath.Join(envsDir, trustedFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &trustedFile{Version: trustedVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var list trustedFile
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON. Delete the file and confirm your project folders again", path)
	}
	if list.Version != trustedVersion {
		return nil, fmt.Errorf("%s has version %d, which is not supported. Update envs", path, list.Version)
	}
	return &list, nil
}
