import json
import logging
import os
import yaml

# from .templates import add_dns_entry

def write_policies_to_files(policies, patternMatches):
    directory = "./policies"
    
    if not os.path.exists(directory):
        os.makedirs(directory)

    for policy_name, policy_data in policies.items():
        if 'ingress' not in policy_data['spec']:
            policy_data['spec']['ingress'] = [{}]
        if 'egress' not in policy_data['spec']:
            policy_data['spec']['egress'] = [{}]

        ordered_policy_data = reorder_policy(policy_data)

        filename = os.path.join(directory, f"{policy_name}.yaml")

        with open(filename, 'w') as file:
            yaml.dump(ordered_policy_data, file, default_flow_style=False, sort_keys=False)
            logging.info(f"Policy written to {filename}")
    
    json_data = json.dumps({"patterns": patternMatches}, indent=4)
    with open('report.json', 'w') as file:
        file.write(json_data)


def reorder_policy(policy):
    spec = policy.get('spec', {})
    ordered_spec = {}

    if 'endpointSelector' in spec:
        ordered_spec['endpointSelector'] = spec['endpointSelector']

    if 'ingress' in spec:
        ordered_spec['ingress'] = spec['ingress']
    if 'egress' in spec:
        ordered_spec['egress'] = spec['egress']

    policy['spec'] = ordered_spec
    return policy