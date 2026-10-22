#!/usr/bin/env bash
# Install the system libraries a cgo-enabled Linux build of this tree needs.
#
# Two packages depend on cgo and on headers no GitHub-hosted ubuntu runner
# ships:
#
#   cmd/agentui is a Fyne application. Fyne's GLFW driver binds to OpenGL through
# github.com/go-gl/gl, which is cgo-only, and GLFW's X11 backend includes
# X11/Xlib.h. A GitHub-hosted ubuntu runner has neither the X11 nor the GL
# development headers preinstalled, so without this the package does not build
# and both `go vet ./...` and `go test ./...` fail on it.
#
#   github.com/hillu/go-yara (pulled in by the scanner) needs libyara's
#   pkg-config metadata; `go vet ./...` with cgo on fails on it otherwise.
#
# The X11 and GL packages are headers and static metadata only — nothing here
# needs a display or a running X server, and no test in cmd/agentui opens a
# window.
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
	echo "setup_linux_cgo_deps.sh: no apt-get; skipping (non-Debian runner)" >&2
	exit 0
fi

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
	libgl1-mesa-dev \
	xorg-dev \
	libyara-dev

echo "cgo build dependencies installed:"
pkg-config --modversion gl x11 xcursor xrandr xinerama xi xxf86vm yara 2>/dev/null || true
