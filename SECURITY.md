# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it by opening a private issue or contacting the maintainers directly. Do not open a public issue for security vulnerabilities.

## Scope

This repository contains GitOps configuration manifests. Security concerns include:

- Leaked credentials or secrets committed to the repository
- Overly permissive RBAC or network policies in addon configurations
- Kyverno policy bypasses or misconfigurations
- Supply chain risks from Helm chart references
