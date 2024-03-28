import logging
import os
import yaml

from .templates import add_dns_entry

def write_policies_to_files(policies):
    directory = "./policies"
    
    if not os.path.exists(directory):
        os.makedirs(directory)

    for policy_name, policy_data in policies.items():
        ordered_policy_data = reorder_policy(policy_data)
        policies[policy_name] = add_dns_entry(policy_data)

        filename = os.path.join(directory, f"{policy_name}.yaml")

        with open(filename, 'w') as file:
            yaml.dump(ordered_policy_data, file, default_flow_style=False, sort_keys=False)
            logging.info(f"Policy written to {filename}")

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