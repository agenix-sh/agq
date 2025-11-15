# Template Files for AGX and AGW Repositories

This directory contains the complete CI/CD setup for the AGX ecosystem. Copy these files to AGX and AGW repos with minimal changes.

---

## Files to Copy

### 1. Workflow Files
Copy to `.github/workflows/`:
- `ci.yml` - Main CI workflow (build + test all platforms)
- `pr-checks.yml` - PR validation and quality gates
- `release.yml` - Release build and asset publishing

### 2. Configuration Files
Copy to repository root:
- `rust-toolchain.toml` - Rust version specification
- `.github/CICD_SETUP.md` - Complete CI/CD documentation

### 3. Cargo.toml Updates
Add to `[package]` section:
```toml
rust-version = "1.82"
```

Add/update `[profile]` sections:
```toml
[profile.release]
overflow-checks = true
lto = true
codegen-units = 1

[profile.dev]
overflow-checks = true
```

---

## Customization Required

### For AGX Repository

**In all workflow files**, replace:
- `agq` → `agx`
- `AGQ` → `AGX`

**Example changes:**
```yaml
# ci.yml
name: agq-${{ matrix.os }}-${{ matrix.arch }}
# becomes:
name: agx-${{ matrix.os }}-${{ matrix.arch }}

# release.yml
asset_name: agq-macos-arm64
# becomes:
asset_name: agx-macos-arm64
```

**PR title validation regex:**
```yaml
# pr-checks.yml line ~16
if [[ ! "$PR_TITLE" =~ ^AGX-[0-9]+: ]]; then
```

### For AGW Repository

**Same replacements:**
- `agq` → `agw`
- `AGQ` → `AGW`

**PR title validation regex:**
```yaml
# pr-checks.yml line ~16
if [[ ! "$PR_TITLE" =~ ^AGW-[0-9]+: ]]; then
```

---

## File-by-File Changes

### `ci.yml`
Search and replace:
- Line 1: `name: CI` → (no change)
- Line 72: `name: agq-${{ matrix.os }}-${{ matrix.arch }}`
  - AGX: `name: agx-${{ matrix.os }}-${{ matrix.arch }}`
  - AGW: `name: agw-${{ matrix.os }}-${{ matrix.arch }}`
- Line 75: `target/${{ matrix.target }}/release/agq`
  - AGX: `target/${{ matrix.target }}/release/agx`
  - AGW: `target/${{ matrix.target }}/release/agw`
- Line 76: `target/${{ matrix.target }}/release/agq.exe` (keep for Windows if needed)

### `pr-checks.yml`
Search and replace:
- Line 16: `if [[ ! "$PR_TITLE" =~ ^AGQ-[0-9]+: ]]; then`
  - AGX: `if [[ ! "$PR_TITLE" =~ ^AGX-[0-9]+: ]]; then`
  - AGW: `if [[ ! "$PR_TITLE" =~ ^AGW-[0-9]+: ]]; then`
- Line 18: `'AGQ-XXX:'`
  - AGX: `'AGX-XXX:'`
  - AGW: `'AGW-XXX:'`

### `release.yml`
Search and replace:
- Line 29: `release_name: AGQ v${{ steps.get_version.outputs.version }}`
  - AGX: `release_name: AGX v${{ steps.get_version.outputs.version }}`
  - AGW: `release_name: AGW v${{ steps.get_version.outputs.version }}`
- Line 34: `AGQ v${{ steps.get_version.outputs.version }}`
  - AGX: `AGX v${{ steps.get_version.outputs.version }}`
  - AGW: `AGW v${{ steps.get_version.outputs.version }}`
- Line 63: `binary_name: agq`
  - AGX: `binary_name: agx`
  - AGW: `binary_name: agw`
- Line 64: `asset_name: agq-macos-arm64`
  - AGX: `asset_name: agx-macos-arm64`
  - AGW: `asset_name: agw-macos-arm64`
- Repeat for all 4 platform entries (lines 69, 76, 83)

### `CICD_SETUP.md`
Search and replace:
- **All instances** of `AGQ` → `AGX` or `AGW`
- **All instances** of `agq` → `agx` or `agw`
- Update examples and paths accordingly

### `rust-toolchain.toml`
- **No changes needed** - identical across all repos

---

## Automation Script

For quick setup, use this script:

### For AGX:
```bash
#!/bin/bash
REPO_NAME="agx"
REPO_CODE="AGX"

# In the target repo root
mkdir -p .github/workflows

# Copy and replace
for file in ci.yml pr-checks.yml release.yml; do
  sed "s/agq/$REPO_NAME/g; s/AGQ/$REPO_CODE/g" \
    ../agq/.github/workflows/$file > .github/workflows/$file
done

cp ../agq/.github/CICD_SETUP.md .github/
sed -i '' "s/agq/$REPO_NAME/g; s/AGQ/$REPO_CODE/g" .github/CICD_SETUP.md

cp ../agq/rust-toolchain.toml .

echo "✅ CI/CD setup complete for $REPO_CODE"
```

### For AGW:
```bash
#!/bin/bash
REPO_NAME="agw"
REPO_CODE="AGW"

# Same script as above, different variables
# ...
```

---

## Verification Checklist

After copying files to AGX or AGW:

- [ ] All workflow files in `.github/workflows/`
- [ ] `rust-toolchain.toml` in root
- [ ] `Cargo.toml` updated with `rust-version`
- [ ] All `agq`/`AGQ` references replaced
- [ ] PR title regex matches repo (AGX-XXX or AGW-XXX)
- [ ] Binary names correct in release workflow
- [ ] Asset names correct (agx-* or agw-*)
- [ ] Commit and push to trigger CI
- [ ] Verify first CI run completes successfully

---

## Testing the Setup

### 1. Create a Test Branch
```bash
git checkout -b test-ci-setup
```

### 2. Make a Small Change
```bash
echo "# CI Test" >> README.md
git add README.md
git commit -m "Test: Verify CI/CD setup"
```

### 3. Push and Create PR
```bash
git push -u origin test-ci-setup
gh pr create --title "AGX-000: Test CI/CD setup" --body "Testing CI workflows"
```

### 4. Verify Workflows Run
- Check GitHub Actions tab
- Ensure all jobs complete successfully
- Verify artifacts are generated
- Check PR checks show green

### 5. Clean Up
```bash
gh pr close --delete-branch
```

---

## Common Issues

### Issue: Wrong binary name in artifacts
**Symptom:** Release creates `agq` binary instead of `agx`/`agw`
**Fix:** Check `release.yml` line 63+ for correct `binary_name`

### Issue: PR title validation fails
**Symptom:** PR checks fail with "PR title must start with..."
**Fix:** Update regex in `pr-checks.yml` line 16

### Issue: Cross-compilation fails on Linux ARM64
**Symptom:** Linker error for `aarch64-unknown-linux-gnu`
**Fix:** Verify `ci.yml` lines 56-59 install cross-compilation tools

---

## Support

Questions about this template:
- See `.github/CICD_SETUP.md` for detailed documentation
- Check AGQ repository for reference implementation
- Create issue in respective repository

---

**Template Version:** 1.0
**Last Updated:** 2025-11-15
**Maintained By:** AGX Core Team
