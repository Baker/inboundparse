# Contributing to InboundParse

Thank you for your interest in contributing to **InboundParse** – your ideas, code, and feedback help make the project better for everyone! This guide will help you get set up, understand the workflow, and make your contribution count.

---

## 🤝 How to Contribute

We appreciate all kinds of contributions:

- Reporting bugs
- Suggesting features and improvements
- Submitting pull requests (PRs) for code, documentation, or examples
- Improving tests or infrastructure
- Sharing your use case or feedback

---

## 🚀 Getting Started

### 1. Fork & Clone

1. Fork the repository on GitHub.
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/inboundparse.git
   cd inboundparse
   ```

3. Add the upstream remote for updates:
   ```bash
   git remote add upstream https://github.com/baker/inboundparse.git
   ```

### 2. Set Up Your Environment

- **Ensure you have a Go toolchain that matches `go.mod` (currently Go 1.27.x).**
- Install dependencies:
  ```bash
  make deps
  ```
- Build the project:
  ```bash
  make build
  ```

**Key Dependencies:**
- `github.com/failsafe-go/failsafe-go` - Webhook resilience patterns (retry, rate limiting, circuit breaker)
- `github.com/rs/zerolog` - High-performance structured logging
- `github.com/getsentry/sentry-go` - Error tracking and performance monitoring
- `github.com/prometheus/client_golang` - Metrics collection

### 3. Run Tests

- To run all tests:
  ```bash
  make test
  ```
- For coverage summary:
  ```bash
  make coverage
  ```

---

## 🔄 Pull Request Checklist

- **Keep your branch up to date**:  
  Rebase or merge `upstream/main` regularly to minimize conflicts.

- **Format your code**:  
  ```bash
  make format
  ```

- **Lint your code**:  
  ```bash
  make lint
  ```

_We also have `make fl` which does both._

- **Include tests**:  
  Add or update tests for new features and bug fixes.

- **Update documentation**:  
  Update the README or other docs if you add/change features.

- **Describe your changes**:  
  Use clear commit messages and fill out the PR template thoroughly.

---

## 💡 Tips for a Great Contribution

- Small, focused PRs are easier to review.
- Reference related issues in your PR description (`Fixes #123`).
- Discuss big changes or refactors with maintainers before starting.

---

## 📝 Code Style & Guidelines

- Write clean, idiomatic Go (see `make fl`).
- Prefer clarity over cleverness.
- Use descriptive variable and function names.
- Keep functions short and focused.
- Leverage existing patterns in the codebase.
- Follow the [Go style guide](https://github.com/golang/go/wiki/CodeReviewComments).

---

## 🛠 Useful Make Targets

| Command             | Purpose                         |
| ------------------- | ------------------------------ |
| `make deps`         | Install dependencies            |
| `make build`        | Build binaries                  |
| `make run-dev`      | Run with development settings   |
| `make test`         | Run tests                       |
| `make coverage`     | Run tests with coverage report  |
| `make format`       | Format code                     |
| `make lint`         | Run linter and vulnerability scan |
| `make vet`          | Vet the code                    |
| `make fl`           | Format, lint, and vet code      |
| `make check`        | Run deps, linters, and vulncheck |
| `make clean`        | Clean build artifacts           |
| `make up`           | Start dev stack (Docker)        |
| `make down`         | Stop dev stack                  |
| `make dev`          | Restart dev stack               |
| `make status`       | Show service status             |
| `make verify-deps`  | Verify dependency status        |
| `make docker-build` | Build Docker image              |
| `make ci`           | Run CI workflow                 |


---

## 🙋 Need Help?

- **File an [issue](https://github.com/baker/inboundparse/issues) or start a discussion** if you have questions, ideas, or need guidance.
- For security issues, please report privately.

Thank you for improving InboundParse!