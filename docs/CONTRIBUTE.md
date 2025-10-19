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

- **Ensure you have Go >= 1.20 installed.**
- Install dependencies:
  ```bash
  make deps
  ```
- Build the project:
  ```bash
  make build
  ```

### 3. Run Tests

- To run all tests:
  ```bash
  make test
  ```
- For coverage and additional checks:
  ```bash
  make test-coverage
  ```

---

## 🔄 Pull Request Checklist

- **Keep your branch up to date**:  
  Rebase or merge `upstream/main` regularly to minimize conflicts.

- **Follow Go formatting**:  
  Run `go fmt ./...` and `go vet ./...` before submitting.

- **Lint your code**:  
  ```bash
  make lint
  ```

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

- Write clean, idiomatic Go (see `make lint`).
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
| `make run`          | Run server (prod config)        |
| `make run-dev`      | Run with development settings   |
| `make lint`         | Run linter                      |
| `make test`         | Run tests                       |
| `make test-coverage`| Run tests with coverage report  |
| `make up`           | Start dev stack (Docker)        |
| `make down`         | Stop dev stack                  |


---

## 🙋 Need Help?

- **File an [issue](https://github.com/baker/inboundparse/issues) or start a discussion** if you have questions, ideas, or need guidance.
- For security issues, please report privately.

Thank you for improving InboundParse!