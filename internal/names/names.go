// Package names validates project, environment, and key names.
package names

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	pathName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	keyName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func Project(name string) error {
	return checkPathName("project", name)
}

func Environment(name string) error {
	return checkPathName("environment", name)
}

func Key(name string) error {
	if !keyName.MatchString(name) {
		return fmt.Errorf("invalid key name %q. A key name uses letters, digits, and \"_\", and does not start with a digit", name)
	}
	return nil
}

func checkPathName(kind, name string) error {
	if !pathName.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid %s name %q. A %s name uses lowercase letters, digits, \".\", \"_\", and \"-\", starts with a letter or digit, and does not contain \"..\"", kind, name, kind)
	}
	return nil
}
