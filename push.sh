#!/usr/bin/env bash
# Usage: ./push.sh
git remote add origin https://github.com/bloodymranish-art/dhokha-radar.git 2>/dev/null
git branch -M main && git push -u origin main
