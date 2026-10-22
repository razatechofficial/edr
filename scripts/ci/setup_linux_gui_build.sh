#!/usr/bin/env bash
# Install the system headers cmd/agentui needs to compile on Linux.
#
# cmd/agentui is a Fyne application. Fyne's GLFW driver binds to OpenGL through
# github.com/go-gl/gl, which is cgo-only, and GLFW's X11 backend includes
# X11/Xlib.h. A GitHub-hosted ubuntu runner has neither the X11 nor the GL
# development headers preinstalled, so without this the package does not build
# and both `go vet ./...` and `go test ./...` fail on it.
#
# These are headers and static metadata only — nothing here needs a display or
# a running X server, and no test in cmd/agentui opens a window.
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
	echo "setup_linux_gui_build.sh: no apt-get; skipping (non-Debian runner)" >&2
	exit 0
fi

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
	libgl1-mesa-dev \
	xorg-dev

echo "Fyne/GLFW build headers installed:"
pkg-config --modversion gl x11 xcursor xrandr xinerama xi xxf86vm 2>/dev/null || true
