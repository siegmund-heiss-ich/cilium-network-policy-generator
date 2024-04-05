# Cilium Network Policy Generator

This application generates valid cilium network policies from [exported Hubble flows](https://docs.cilium.io/en/latest/observability/hubble-exporter/).

All paths of communication are retrieved from flows, including namespace, cluster, and external communication.

To fine-tune the generated policies, the [policy editor](https://editor.networkpolicy.io/) of Isovalent is preferable.

## Usage

On Linux/macOS: `python3 generate.py <path/to/exported/flowLogs>`
On Windows: `python generate.py <path/to/exported/flowLogs>`

The generated policies will be stored in `./policies`.
In the root folder, you can find a report of the policy generation process.

## Contribute

If you have any suggestions for improvements, just create a PullRequest or an Issue.
