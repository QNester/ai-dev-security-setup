// Package templates embeds declarative platform configuration templates.
package templates

import "embed"

// FS contains Linux unit/nftables and macOS launchd/Seatbelt templates.
//
//go:embed linux/* darwin/*
var FS embed.FS
