// +build linux darwin netbsd openbsd netbsd freebsd

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

func FindExecutable() (rv string, err error) {
	paths := strings.Split(os.Getenv("PATH"), ":")
	for _, dirname := range paths {
		if filenames, ok := ioutil.ReadDir(dirname); nil != ok {
			return "", ok
		} else {
			for _, fname := range filenames {
				if fname.Name() == "gpg2" || fname.Name() == "gpg" {
					return dirname +
						string(os.PathSeparator) +
						fname.Name(), nil
				}
			}
		}
	}
	return "", errors.New("gpg not found")
}
