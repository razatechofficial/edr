#!/bin/bash
set -e
systemctl stop edr-agent || true
systemctl disable edr-agent || true
