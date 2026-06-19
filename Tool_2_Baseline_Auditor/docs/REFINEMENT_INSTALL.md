# Refinement Installation Guide

These steps assume the repository is located at:

`/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools`

## 1. Protect the current release

```bash
cd "/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools"
git status --short
git pull --rebase origin main
git switch -c tool2-v2.0-refinement
git tag tool2-v1.1.0-backup
```

The working tree should be clean before replacing files.

## 2. Copy the refinement files

Extract the bundle, then run from the extracted `Security_Tools` directory:

```bash
rsync -av --delete \
  Tool_2_Baseline_Auditor/ \
  "/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools/Tool_2_Baseline_Auditor/"

mkdir -p \
  "/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools/.github/workflows"

cp .github/workflows/tool2-tests.yml \
  "/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools/.github/workflows/tool2-tests.yml"
```

## 3. Validate before committing

```bash
cd "/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools/Tool_2_Baseline_Auditor"

python3 -m py_compile baseline_auditor.py baseline_auditor_core/*.py
python3 -m unittest discover -s tests -v

rm -rf output_secure output_insecure output_malformed

python3 baseline_auditor.py samples/secure_linux -o output_secure
python3 baseline_auditor.py samples/insecure_linux -o output_insecure
python3 baseline_auditor.py samples/malformed_linux -o output_malformed

python3 baseline_auditor.py --version
python3 baseline_auditor.py --list-profiles
```

Expected secure result: 15 passed, 0 failed, 100%.

Expected insecure result: 0 passed, 15 failed, 0%, with 2 critical,
4 high, 6 medium, and 3 low findings.

The malformed sample should produce explicit failed findings and should not
crash.

## 4. Verify severity-aware exit behavior

```bash
python3 baseline_auditor.py samples/secure_linux \
  -o output_secure \
  --fail-on-findings \
  --fail-level high
echo "secure exit code: $?"

python3 baseline_auditor.py samples/insecure_linux \
  -o output_insecure \
  --fail-on-findings \
  --fail-level high
echo "insecure exit code: $?"
```

Expected: secure `0`, insecure `1`.

## 5. Inspect changes

```bash
cd "/Users/adamsea1/Desktop/Security Tool Dev - CSC 842/Security_Tools"
git status --short
git diff --stat
git diff -- Tool_2_Baseline_Auditor/README.md
```

## 6. Commit and push the refinement branch

```bash
git add Tool_2_Baseline_Auditor \
        .github/workflows/tool2-tests.yml

git commit -m "Refine baseline auditor based on peer feedback"
git push -u origin tool2-v2.0-refinement
```

After reviewing the branch on GitHub, merge it into `main` or create a pull
request.
