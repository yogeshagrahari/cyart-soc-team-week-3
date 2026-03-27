#!/bin/bash
# ============================================================
# CYART SOC Team — GitHub Repository Setup Script
# Run this script to initialize and push to GitHub
# ============================================================

set -e

REPO_NAME="cyart-soc-team"
GITHUB_USERNAME="YOUR_GITHUB_USERNAME"   # ← CHANGE THIS

echo "╔══════════════════════════════════════════╗"
echo "║   CYART SOC — GitHub Repo Setup         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ─── STEP 1: Install Git (if not present) ─────────────────
echo "[1/6] Checking Git installation..."
if ! command -v git &> /dev/null; then
    sudo apt install git -y
fi
git --version

# ─── STEP 2: Configure Git identity ───────────────────────
echo ""
echo "[2/6] Configuring Git identity..."
echo "  (Edit these values in the script before running)"
git config --global user.name "CYART SOC Analyst"
git config --global user.email "soc@cyart.team"

# ─── STEP 3: Initialize repository ───────────────────────
echo ""
echo "[3/6] Initializing local repository..."
cd cyart-soc-team
git init
git branch -M main

# ─── STEP 4: Stage all files ──────────────────────────────
echo ""
echo "[4/6] Staging all files..."
git add .
git status

# ─── STEP 5: Initial commit ───────────────────────────────
echo ""
echo "[5/6] Creating initial commit..."
git commit -m "feat: Add Week 2 - Practical SOC Application

- Lab 1: Advanced Log Analysis (Elastic Security, GeoIP, Anomaly Rules)
- Lab 2: Threat Intelligence Integration (Wazuh + AlienVault OTX)
- Lab 3: Incident Escalation Practice (TheHive + SOAR)
- Lab 4: Alert Triage with Threat Intel (VirusTotal + OTX)
- Lab 5: Evidence Preservation (Velociraptor + FTK Imager)
- Lab 6: Capstone - Full SOC Workflow Simulation (CVE-2007-2447)

Includes:
- 6 detailed workflow files with complete commands
- 6 PDF lab reports
- Elastic, Wazuh, Velociraptor cheatsheets
- Master notes with all tool references
- Screenshot guide for all labs"

# ─── STEP 6: Push to GitHub ───────────────────────────────
echo ""
echo "[6/6] Pushing to GitHub..."
echo ""
echo "Before running this step:"
echo "  1. Go to: https://github.com/new"
echo "  2. Repository name: $REPO_NAME"
echo "  3. Visibility: Private (recommended for SOC training data)"
echo "  4. DO NOT initialize with README (we have our own)"
echo "  5. Click: Create Repository"
echo ""
echo "Then run these commands manually:"
echo ""
echo "  git remote add origin https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git"
echo "  git push -u origin main"
echo ""
echo "Or if using SSH keys:"
echo "  git remote add origin git@github.com:${GITHUB_USERNAME}/${REPO_NAME}.git"
echo "  git push -u origin main"
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║    Local repo ready to push!           ║"
echo "╚══════════════════════════════════════════╝"
