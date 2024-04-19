# Cilium Network Policy Generator

This application generates valid cilium network policies from [exported Hubble flows](https://docs.cilium.io/en/latest/observability/hubble-exporter/).

All paths of communication are retrieved from flows, including namespace, cluster, and external communication.

To fine-tune the generated policies, the [policy editor](https://editor.networkpolicy.io/) of Isovalent is preferable.

## Usage (L3/L4)

On Linux/macOS: `python3 generate.py <path/to/exported/flowLogs>`

On Windows: `python generate.py <path/to/exported/flowLogs>`

The generated policies will be stored in `./policies`.
In the root folder, you can find a report of the policy generation process.

## L7

<b>Retrieve L7 flows:</b>

To retrieve L7 flows, you must first specify the appropriate ports for your application. Edit the `port_protocol_map` in the file `./src/add_rule.py` to select the correct ports.
Once the ports are set, execute the policy generation using the `-L7allowAll` flag.
Apply the new policies in Cilium to retrieve new flows containing L7 information.

<b>Retrieve L7 policies (The step before is mandatory):</b>

After retrieving flows containing L7 info, add the `-L7` flag to generate policies with strict L7 rules.

### Considerations

It should work fine, as long as there is enough data to generate the policies from.
I suggest a flow exporting period where every functionality of your application is tested.
Also, the scaling of the application should be triggered, to make sure flows corresponding to creating new instances are present.

## Contribute

If you have any suggestions for improvements, just create a PullRequest or an Issue.
