---
title: Dashboard
nav_order: 1
parent: Portal
---

# Dashboard

The portal dashboard provides a security posture overview across all registered developer machines.

## Overview

The dashboard is the landing page after login. It shows aggregate data from all hosts reporting to the portal under your customer key.

![Dashboard](../images/Dashboard.png)

## Host Status Indicators

Each registered host displays a status indicator based on its heartbeat:

| Status | Color | Meaning |
|--------|-------|---------|
| Online | Green | Heartbeat received within the expected interval |
| Stale | Yellow | Heartbeat is overdue but within tolerance |
| Offline | Red | No heartbeat received beyond tolerance threshold |

![Host Status](../images/Host%20Status.png)

## Dashboard Metrics

The dashboard displays:

- **Total hosts** -- Number of registered machines
- **Total extensions** -- Aggregate extension count across all hosts
- **Dangerous extensions** -- Extensions with Critical or High risk permissions
- **Exposed secrets** -- Active (unresolved) secret findings
- **Vulnerable packages** -- Packages with known CVEs
- **AI components** -- Detected AI tools and MCP servers

## IDE Distribution

A breakdown of IDE usage across your organization, showing which IDEs are most common and their extension counts.

## Tamper Alerts

If any daemon detects modification to its binary, config, or service files, a tamper alert appears prominently on the dashboard.

## CSV Export

All dashboard data views can be exported to CSV using the export button.
