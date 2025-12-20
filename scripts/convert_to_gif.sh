#!/bin/bash

INPUT="dashboard_demo.mp4"
OUTPUT="dashboard_demo.gif"

if [ ! -f "$INPUT" ]; then
    echo "❌ Error: Input file '$INPUT' not found."
    exit 1
fi

echo "🎬 Converting '$INPUT' to '$OUTPUT'..."
echo "   This may take a moment depending on the video length..."

# Convert to GIF with optimizations:
# 1. fps=15: Reduce frame rate to 15 for smaller size
# 2. scale=800:-1: Resize width to 800px (maintain aspect ratio)
# 3. palettegen/paletteuse: Generate optimal color palette for better quality
ffmpeg -i "$INPUT" \
    -vf "fps=15,scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
    -y "$OUTPUT"

echo "✅ GIF created: $OUTPUT"
ls -lh "$OUTPUT"
