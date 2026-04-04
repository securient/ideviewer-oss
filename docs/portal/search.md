---
title: Search
nav_order: 3
parent: Portal
---

# Global Search

The portal provides a global search that queries across all data types in a single search box.

## Searchable Entities

| Entity | Searched Fields |
|--------|----------------|
| **Hosts** | Hostname, OS, platform |
| **Extensions** | Extension name, publisher, IDE |
| **Packages** | Package name, version, manager |
| **AI Components** | Component name, tool, type |
| **MCP Servers** | Server name, configuration |

## How to Use

1. Click the search icon or press `/` to focus the search bar
2. Type your query (minimum 2 characters)
3. Results are grouped by entity type
4. Click a result to navigate to the relevant detail view

## Examples

- Search `eslint` to find all hosts with the ESLint extension or npm package
- Search `aws` to find secrets of type AWS key or packages related to AWS
- Search a hostname to jump directly to that host's detail page
- Search `claude` to find all Claude Code components across hosts

![Search](../images/Search%20Extension.png)
