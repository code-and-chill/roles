package roles

import "fmt"

type PermissionMode string

const (
	Create PermissionMode = "Create"
	Read   PermissionMode = "Read"
	Update PermissionMode = "Update"
	Delete PermissionMode = "Delete"
	CRUD   PermissionMode = "CRUD"
)

type Permission struct {
	Role         *Role
	AllowedRoles map[PermissionMode][]string
	DeniedRoles  map[PermissionMode][]string
}

func includeRoles(roles []string, values []string) bool {
	for _, role := range roles {
		if role == "*" {
			return true
		}

		for _, value := range values {
			if value == role {
				return true
			}
		}
	}
	return false
}

func (permission *Permission) Concat(newPermission *Permission) *Permission {
	var result = Permission{
		Role:         Global,
		AllowedRoles: map[PermissionMode][]string{},
		DeniedRoles:  map[PermissionMode][]string{},
	}

	var appendRoles = func(p *Permission) {
		if p != nil {
			result.Role = p.Role

			for mode, roles := range p.DeniedRoles {
				result.DeniedRoles[mode] = append(result.DeniedRoles[mode], roles...)
			}

			for mode, roles := range p.AllowedRoles {
				result.AllowedRoles[mode] = append(result.AllowedRoles[mode], roles...)
			}
		}
	}

	appendRoles(newPermission)
	appendRoles(permission)
	return &result
}

func (permission *Permission) Allow(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Allow(Create, roles...).Allow(Read, roles...).Allow(Update, roles...).Allow(Delete, roles...)
	}

	if permission.AllowedRoles[mode] == nil {
		permission.AllowedRoles[mode] = []string{}
	}
	permission.AllowedRoles[mode] = append(permission.AllowedRoles[mode], roles...)
	return permission
}

func (permission *Permission) Deny(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Deny(Create, roles...).Deny(Read, roles...).Deny(Update, roles...).Deny(Delete, roles...)
	}

	if permission.DeniedRoles[mode] == nil {
		permission.DeniedRoles[mode] = []string{}
	}

	permission.DeniedRoles[mode] = append(permission.DeniedRoles[mode], roles...)
	return permission
}

func (permission Permission) HasPermission(mode PermissionMode, roles ...interface{}) bool {
	var roleNames []string
	for _, role := range roles {
		if r, ok := role.(string); ok {
			roleNames = append(roleNames, r)
		} else if roler, ok := role.(Roler); ok {
			roleNames = append(roleNames, roler.GetRoles()...)
		} else {
			fmt.Printf("invalid role %#v\n", role)
			return false
		}
	}

	if len(permission.DeniedRoles) != 0 {
		if DeniedRoles := permission.DeniedRoles[mode]; DeniedRoles != nil {
			if includeRoles(DeniedRoles, roleNames) {
				return false
			}
		}
	}

	if len(permission.AllowedRoles) == 0 {
		return true
	}

	if AllowedRoles := permission.AllowedRoles[mode]; AllowedRoles != nil {
		if includeRoles(AllowedRoles, roleNames) {
			return true
		}
	}

	return false
}
