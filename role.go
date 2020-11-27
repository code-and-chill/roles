package roles

import (
	"fmt"
	"net/http"
)

type Role struct {
	definitions map[string]Checker
}

type Checker func(req *http.Request, user interface{}) bool

func New() *Role {
	return &Role{}
}

func (role *Role) Register(name string, fc Checker) {
	if role.definitions == nil {
		role.definitions = map[string]Checker{}
	}

	definition := role.definitions[name]
	if definition != nil {
		fmt.Printf("Role `%v` already defined, overwrited it!\n", name)
	}
	role.definitions[name] = fc
}

func (role *Role) NewPermission() *Permission {
	return &Permission{
		Role:         role,
		AllowedRoles: map[PermissionMode][]string{},
		DeniedRoles:  map[PermissionMode][]string{},
	}
}

func (role *Role) Allow(mode PermissionMode, roles ...string) *Permission {
	return role.NewPermission().Allow(mode, roles...)
}

func (role *Role) Deny(mode PermissionMode, roles ...string) *Permission {
	return role.NewPermission().Deny(mode, roles...)
}

func (role *Role) Get(name string) (Checker, bool) {
	fc, ok := role.definitions[name]
	return fc, ok
}

func (role *Role) Remove(name string) {
	delete(role.definitions, name)
}

func (role *Role) Reset() {
	role.definitions = map[string]Checker{}
}

func (role *Role) MatchedRoles(req *http.Request, user interface{}) (roles []string) {
	if definitions := role.definitions; definitions != nil {
		for name, definition := range definitions {
			if definition(req, user) {
				roles = append(roles, name)
			}
		}
	}
	return
}

func (role *Role) HasRole(req *http.Request, user interface{}, roles ...string) bool {
	if definitions := role.definitions; definitions != nil {
		for _, name := range roles {
			if definition, ok := definitions[name]; ok {
				if definition(req, user) {
					return true
				}
			}
		}
	}
	return false
}
