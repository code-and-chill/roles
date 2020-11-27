package roles

var Global = &Role{}

func Allow(mode PermissionMode, roles ...string) *Permission {
	return Global.Allow(mode, roles...)
}

func Deny(mode PermissionMode, roles ...string) *Permission {
	return Global.Deny(mode, roles...)
}
