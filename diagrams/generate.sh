#!/bin/bash
# Generate PNG diagrams from PlantUML source files.
# Output goes to diagrams/ — FastAPI serves them at /static/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate plantuml — try common locations
if command -v plantuml &>/dev/null; then
  PUML="plantuml"
elif [ -f "$HOME/.local/bin/plantuml" ]; then
  PUML="$HOME/.local/bin/plantuml"
elif [ -f "/usr/local/bin/plantuml" ]; then
  PUML="/usr/local/bin/plantuml"
elif [ -f "/opt/homebrew/bin/plantuml" ]; then
  PUML="/opt/homebrew/bin/plantuml"
else
  # Try java -jar if plantuml.jar is nearby
  JAR=$(find "$HOME" -name "plantuml*.jar" 2>/dev/null | head -1)
  if [ -n "$JAR" ]; then
    PUML="java -jar $JAR"
  else
    echo "[generate] ERROR: plantuml not found."
    echo "  Install: brew install plantuml  (Mac)"
    echo "           sudo dnf install plantuml  (RHEL)"
    echo "           sudo apt install plantuml  (Debian)"
    exit 1
  fi
fi

echo "[generate] Using: $PUML"

for puml in "$SCRIPT_DIR"/*.puml; do
  base=$(basename "$puml" .puml)
  echo "[generate] Rendering $base.puml → $base.png"
  $PUML -tpng -o "$SCRIPT_DIR" "$puml"
done

echo "[generate] Done. Reload the Architecture tab in Satan."
