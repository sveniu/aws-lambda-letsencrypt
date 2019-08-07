package validation

import (
	"fmt"
	"sync"

	"golang.org/x/crypto/acme"
)

type Validator struct {
	ACMEClient *acme.Client
	Token      string
}

type Backend interface {
	Configure(map[string]interface{}) error
	ValidateIdentifier(*acme.Client, string, string) error
}

type BackendFactory func() (Backend, error)

var backendFactoriesMutex sync.RWMutex
var backendFactories = make(map[string]BackendFactory)

func RegisterBackend(
	name string,
	bf BackendFactory,
) {
	// Grab lock.
	backendFactoriesMutex.Lock()
	defer backendFactoriesMutex.Unlock()

	if bf == nil {
		panic(fmt.Sprintf("backend: RegisterBackend('%s', nil)", name))
	}
	if _, dup := backendFactories[name]; dup {
		panic(fmt.Sprintf("backend: Register called twice for backend '%s'", name))
	}
	backendFactories[name] = bf
}

func GetBackend(
	name string,
) (
	Backend,
	error,
) {
	// Grab lock.
	backendFactoriesMutex.Lock()
	defer backendFactoriesMutex.Unlock()

	factoryFunction, found := backendFactories[name]
	if !found {
		return nil, nil
	}
	return factoryFunction()
}

func InitBackend(
	name string,
) (
	Backend,
	error,
) {
	backend, err := GetBackend(name)
	if err != nil {
		return nil, fmt.Errorf("Could not init backend '%s': %+v", name, err)
	}
	if backend == nil {
		return nil, fmt.Errorf("Unknown backend '%s'", name)
	}

	return backend, nil
}
