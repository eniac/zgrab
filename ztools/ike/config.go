package ike

func MakeIKEConfig() *InitiatorConfig {
	ret := new(InitiatorConfig)
	ret.Version = uint16(pkgConfig.Version)
	ret.ModeV1 = pkgConfig.ModeV1
	ret.DHGroup = uint16(pkgConfig.DHGroup)
	ret.Proposals = pkgConfig.Proposals.Get()
	ret.KexValues = pkgConfig.KexValues.Get()
	ret.BuiltIn = pkgConfig.BuiltIn
	return ret
}
