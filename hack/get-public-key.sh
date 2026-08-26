#!/bin/bash

set -e

if [ "$(uname -s)" = "Linux" ]; then
    cat ./key.pub|base64 --wrap 2048
else
    cat ./key.pub|base64
fi
