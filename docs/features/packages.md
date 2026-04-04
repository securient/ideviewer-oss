---
title: Package Inventory & CVE
nav_order: 2
parent: Features
---

# Package Inventory & CVE Scanning

IDEViewer inventories packages from all major package managers, including packages bundled inside IDE extensions, and correlates them with OSV.dev for known vulnerabilities.

## Supported Package Managers

| Language | Manager | Detection |
|----------|---------|-----------|
| Python | pip, pipenv, poetry | Global + project-level |
| Node.js | npm | Global + project + extension-bundled |
| Go | go | `~/go/bin` + `go.mod` |
| Rust | cargo | Global + `Cargo.lock` |
| Ruby | gem | Global + `Gemfile.lock` |
| PHP | composer | `composer.lock` |
| Java | maven | JetBrains plugin JARs |
| macOS | Homebrew | Formula + casks |

## CLI Usage

```bash
# Scan all packages
ideviewer packages

# Output as JSON
ideviewer packages --json

# Only global packages
ideviewer packages --global-only
```

## Extension Dependency Scanning

Standard SCA tools scan project dependencies but miss packages bundled inside IDE extensions. IDEViewer scans:

- **VS Code extensions** -- `node_modules` directories inside each extension folder
- **JetBrains plugins** -- JAR files bundled with each plugin

These packages are tracked with a source of `extension` rather than `project`, so you can distinguish where each dependency comes from.

## CVE Correlation

All discovered packages (both project-level and extension-bundled) are checked against [OSV.dev](https://osv.dev) for known vulnerabilities. Results include:

- CVE identifier
- Severity rating
- Affected version range
- Fixed version (if available)

## npm Lifecycle Hook Detection

IDEViewer flags npm packages that define lifecycle hooks (`preinstall`, `postinstall`, `preuninstall`), which can execute arbitrary code during `npm install`. These are highlighted as a supply chain risk.

## Portal View

In the portal's host detail page, the **Packages** tab shows:

- All packages grouped by manager
- Version information
- Install type (global, project, extension-bundled)
- CVE indicators for vulnerable packages
- **Extension Deps** filter to show only packages bundled inside IDE extensions

Click any package to open the **Package Detail Modal**, which shows:

- Source tracking (which project or extension this package comes from)
- Lifecycle hooks (if any)
- Associated CVEs with severity and links
