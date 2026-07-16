#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scp "$SCRIPT_DIR/k9x_satan.tar.gz" ravinata@192.168.1.98:/home/ravinata/ai/k9x-ecosystem/satan/
