# Cilium Network Policy Generator

This application generates valid cilium network policies from exported Hubble flows.

As of now, just communication within the corresponding Namespaces (incl. kube-dns egress) are written to valid `*.yaml` files.

## Usage

On Linux/macOS: `python3 generate.py <path/to/exported/flowLogs>`

On Windows: `python generate.py <path/to/exported/flowLogs>`
