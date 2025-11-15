# CI/CD Setup Guide for AGX Ecosystem

**Applies to:** AGX, AGQ, AGW repositories
**Version:** 1.0
**Last Updated:** 2025-11-15

---

## Overview

This document describes the **uniform CI/CD setup** across all three AGX ecosystem repositories. All repos use identical GitHub Actions workflows to ensure consistency.

---

## Supported Build Targets

### Tier 1 Platforms (Full Testing)
- **macOS ARM64** (Apple Silicon M1/M2/M3) - `aarch64-apple-darwin`
- **macOS x86_64** (Intel) - `x86_64-apple-darwin`
- **Linux x86_64** - `x86_64-unknown-linux-gnu`

### Tier 2 Platforms (Build Only)
- **Linux ARM64** - `aarch64-unknown-linux-gnu`

**Note:** Tests run on Tier 1 platforms only (native execution). Tier 2 platforms build binaries via cross-compilation.

---

## GitHub Actions Workflows

### 1. **Main CI Workflow** (`.github/workflows/ci.yml`)

**Triggers:**
- Push to `main` branch
- Pull requests to `main`

**Jobs:**

#### `test` (Matrix Build)
Builds and tests across all platforms:

| Platform | Runner | Target | Tests |
|----------|--------|--------|-------|
| macOS ARM64 | `macos-14` | `aarch64-apple-darwin` | ✅ Full |
| macOS x86_64 | `macos-13` | `x86_64-apple-darwin` | ✅ Full |
| Linux x86_64 | `ubuntu-latest` | `x86_64-unknown-linux-gnu` | ✅ Full |
| Linux ARM64 | `ubuntu-latest` | `aarch64-unknown-linux-gnu` | 🔨 Build only |

**Steps:**
1. Checkout code
2. Install Rust toolchain (stable + targets)
3. Cache dependencies (registry, index, build)
4. Install cross-compilation tools (ARM64 Linux)
5. Check formatting (`cargo fmt`)
6. Run clippy with pedantic lints
7. Build debug binary
8. Run tests (Tier 1 only)
9. Build release binary
10. Upload artifacts (7-day retention)

#### `security-audit`
- Runs `cargo audit` for dependency vulnerabilities
- Blocks merge if critical vulnerabilities found

#### `coverage`
- Generates code coverage using `cargo-llvm-cov`
- Uploads to Codecov (requires `CODECOV_TOKEN` secret)
- Does not block merge (informational)

#### `summary`
- Aggregates all job results
- Fails if any critical check fails

---

### 2. **PR Checks Workflow** (`.github/workflows/pr-checks.yml`)

**Triggers:**
- Pull request opened/updated

**Jobs:**

#### `pr-validation`
Validates PR metadata:
- Title format: `AGQ-XXX: Description` (or `AGX-XXX`, `AGW-XXX`)
- Body includes required sections:
  - `## Issue`
  - `## Security Review`
  - `## Testing`

#### `quick-checks`
Fast validation before heavy builds:
- Formatting (`cargo fmt --check`)
- Clippy lints
- Cargo.toml validation

#### `test-coverage-check`
- Generates coverage report
- **Enforces ≥80% threshold**
- Blocks merge if below threshold

#### `security-check`
- Runs `cargo audit`
- Checks for `unsafe` code blocks
- Reports but doesn't auto-block

#### `dependency-check`
- Shows dependency tree
- Detects duplicate dependencies
- Warns but doesn't block

#### `pr-summary`
- Aggregates all check results
- Posts summary to PR
- Blocks merge if critical checks fail

---

### 3. **Release Workflow** (`.github/workflows/release.yml`)

**Triggers:**
- Git tag push: `v*.*.*` (e.g., `v0.1.0`)

**Process:**

1. **Create GitHub Release**
   - Extracts version from tag
   - Creates release with auto-generated notes

2. **Build Release Binaries** (All Platforms)
   - Builds optimized binaries
   - Strips debug symbols
   - Creates `.tar.gz` archives
   - Generates SHA256 checksums

3. **Upload Assets**
   - `agq-macos-arm64.tar.gz` + checksum
   - `agq-macos-x86_64.tar.gz` + checksum
   - `agq-linux-x86_64.tar.gz` + checksum
   - `agq-linux-arm64.tar.gz` + checksum

---

## Configuration Files

### `rust-toolchain.toml`
```toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt", "rust-src"]
profile = "default"
```

**Purpose:** Ensures all developers and CI use same Rust version.

### `Cargo.toml` Requirements
```toml
[package]
rust-version = "1.82"  # Minimum Rust version
edition = "2021"

[profile.release]
overflow-checks = true  # Security: prevent integer overflow
lto = true              # Optimize binary size
codegen-units = 1       # Maximum optimization

[profile.dev]
overflow-checks = true  # Security: detect issues early
```

---

## GitHub Secrets Required

### For All Repos

| Secret | Purpose | Required? |
|--------|---------|-----------|
| `CODECOV_TOKEN` | Upload coverage reports | Optional |
| `GITHUB_TOKEN` | Built-in (auto-provided) | Auto |

**Note:** `GITHUB_TOKEN` is automatically provided by GitHub Actions.

---

## Caching Strategy

All workflows cache:
- **Cargo registry** (`~/.cargo/registry`)
- **Cargo index** (`~/.cargo/git`)
- **Build artifacts** (`target/`)

**Cache keys** include:
- Platform (OS + architecture)
- `Cargo.lock` hash (invalidates on dependency changes)

**Benefits:**
- Faster CI runs (5-10x speedup after first build)
- Reduced network usage
- Cost savings on GitHub Actions minutes

---

## Cross-Compilation Setup

### Linux ARM64 on Ubuntu x86_64

The CI automatically installs cross-compilation toolchain:

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

**Cargo configuration** (auto-handled):
```toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
```

**Why:** Allows building ARM64 Linux binaries on x86_64 GitHub runners.

---

## Local Testing

### Run CI Checks Locally

```bash
# Format check
cargo fmt --all -- --check

# Clippy with full lints
cargo clippy --all-targets -- -D warnings -W clippy::all -W clippy::pedantic

# Build all targets
cargo build --target aarch64-apple-darwin  # macOS ARM64
cargo build --target x86_64-apple-darwin   # macOS x86_64
cargo build --target x86_64-unknown-linux-gnu  # Linux x86_64

# Run tests
cargo test --verbose

# Coverage report
cargo install cargo-llvm-cov
cargo llvm-cov --all-features --workspace --html
# Open target/llvm-cov/html/index.html

# Security audit
cargo install cargo-audit
cargo audit
```

### Install All Targets

```bash
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
```

---

## Workflow Integration with CLAUDE.md

### Per CLAUDE.md Requirements

The CI/CD workflows enforce all CLAUDE.md guidelines:

1. **Testing Requirements**
   - ✅ Minimum 80% coverage enforced
   - ✅ All tests must pass
   - ✅ Security tests included

2. **Code Quality**
   - ✅ `cargo fmt` enforced
   - ✅ Clippy with pedantic lints
   - ✅ No warnings allowed (`-D warnings`)

3. **Security**
   - ✅ `cargo audit` on every PR
   - ✅ Unsafe code detection
   - ✅ Dependency vulnerability scanning

4. **PR Process**
   - ✅ Title format validated
   - ✅ Required sections checked
   - ✅ Dual AI review required (manual)
   - ✅ All checks pass before merge

---

## Status Badges

Add to `README.md`:

```markdown
![CI](https://github.com/agenix-sh/agq/workflows/CI/badge.svg)
![Security Audit](https://github.com/agenix-sh/agq/workflows/Security%20Audit/badge.svg)
[![codecov](https://codecov.io/gh/agenix-sh/agq/branch/main/graph/badge.svg)](https://codecov.io/gh/agenix-sh/agq)
```

---

## Troubleshooting

### Common Issues

#### 1. **Coverage Below 80%**
```
❌ Coverage 75% is below threshold 80%
```

**Solution:** Add more tests or remove untested code.

#### 2. **Clippy Warnings**
```
error: variables can be used directly in the `format!` string
```

**Solution:** Update to inline format args: `format!("{var}")` not `format!("{}", var)`

#### 3. **Security Audit Failure**
```
error: 1 vulnerability found!
```

**Solution:**
```bash
cargo update <vulnerable-crate>
# Or if not fixable:
cargo audit --deny warnings
```

#### 4. **Cross-Compilation Linker Error**
```
error: linker `cc` not found
```

**Solution:** Install cross-compilation toolchain (see above).

#### 5. **Cache Corruption**
```
error: failed to download from `https://...`
```

**Solution:** GitHub Actions → Repository Settings → Actions → Clear caches

---

## Maintenance

### Weekly Tasks
- [ ] Check GitHub Actions usage (stay within limits)
- [ ] Review failed runs
- [ ] Update dependencies (`cargo update`)

### Monthly Tasks
- [ ] Review caching strategy (check hit rates)
- [ ] Update Rust toolchain if needed
- [ ] Review and update workflow files

### Quarterly Tasks
- [ ] Audit all dependencies (`cargo audit`)
- [ ] Review and update target platforms
- [ ] Benchmark CI performance
- [ ] Update this documentation

---

## Migration Checklist

### For Each Repo (AGX, AGQ, AGW)

- [ ] Copy workflow files to `.github/workflows/`
  - [ ] `ci.yml`
  - [ ] `pr-checks.yml`
  - [ ] `release.yml`
- [ ] Create `rust-toolchain.toml` in root
- [ ] Update `Cargo.toml` with `rust-version` and profiles
- [ ] Add status badges to `README.md`
- [ ] Configure Codecov (optional)
- [ ] Test with a dummy PR
- [ ] Verify all platforms build successfully
- [ ] Document repo-specific differences (if any)

---

## Support

**Questions or issues?**
- GitHub Issues: Repo-specific issue tracker
- Review this document: `.github/CICD_SETUP.md`
- Check CLAUDE.md: AI development guidelines

---

**Last Updated:** 2025-11-15
**Maintained By:** AGX Core Team
**Review Cycle:** Quarterly
