# Cilium Network Policy Generator

This application generates valid cilium network policies from [exported Hubble flows](https://docs.cilium.io/en/latest/observability/hubble-exporter/).

All paths of communication are retrieved from flows, including namespace, cluster, and external communication.

To fine-tune the generated policies, the [policy editor](https://editor.networkpolicy.io/) of Isovalent is preferable.

## Usage

On Linux/macOS: `python3 generate.py <path/to/exported/flowLogs>`

On Windows: `python generate.py <path/to/exported/flowLogs>`

The generated policies will be stored in `./policies`.
In the root folder, you can find a report of the policy generation process.

### L3/L4

It should work fine, as long as there is enough data to generate the policies from.
I suggest a flow exporting period where every functionality of your application is tested.
Also, the scaling of the application should be triggered, to make sure flows corresponding to creating new instances are present.

### L7

Currently, there is only an allow all feature, to initially get L7 flows.
The ports have to be selected for your application in `./src/add_rule.py` at `port_protocol_map`, before executing the policy generation with the flag `-L7allowAll`.
This should work fine, if the right ports are chosen manually.

Currently work in progress is the feature, where policies including L7 rules can be created using the flag `-L7`.

## Contribute

If you have any suggestions for improvements, just create a PullRequest or an Issue.
