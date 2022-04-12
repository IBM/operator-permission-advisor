/**
Copyright 2022 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package duplicateHandler

import (
	"errors"
)

var (
	KeyAlreadyExistsError = func() error { return errors.New("key for hashable already exists in the registered map") }()
)

type Hashable interface {
	Hash() string
}

type DuplicateWrapper struct {
	// DuplicateWrapper wraps the built in map object for fast memory access

	// In memory quick search access
	HashMap map[string]Hashable
}

type DuplicateHandler interface {
	CheckForDuplication(h Hashable) bool
	RegisterDuplication(h Hashable) error
	CheckAndRegisterForDuplication(h Hashable) (bool, error)
}

// New is the generator for the DuplicateHandler interface
func New() DuplicateHandler {
	return &DuplicateWrapper{
		HashMap: make(map[string]Hashable),
	}
}

// CheckForDuplication will take a hashable and check to see if it exists in the in memory map
func (d *DuplicateWrapper) CheckForDuplication(h Hashable) bool {
	if d == nil {
		return false
	}
	_, ok := d.HashMap[h.Hash()]
	return ok
}

// RegisterDuplication will register a hashable object in the memory map
func (d *DuplicateWrapper) RegisterDuplication(h Hashable) error {
	if d == nil {
		return nil
	}

	if _, ok := d.HashMap[h.Hash()]; ok {
		return KeyAlreadyExistsError
	}

	d.HashMap[h.Hash()] = h

	return nil
}

// CheckAndRegisterForDuplication is a wrapper of CheckForDuplication and RegisterDuplication
func (d *DuplicateWrapper) CheckAndRegisterForDuplication(h Hashable) (bool, error) {
	return d.CheckForDuplication(h), d.RegisterDuplication(h)
}
