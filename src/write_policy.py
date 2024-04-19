import json
import logging
import os
import yaml

from .add_rule import add_L7_allowAll

def write_policies_to_files(policies, patternMatches, L7allowAll):
    directory = "./policies"
    
    if not os.path.exists(directory):
        os.makedirs(directory)

    for policy_name, policy_data in policies.items():
        if 'ingress' not in policy_data['spec']:
            policy_data['spec']['ingress'] = [{}]
        if 'egress' not in policy_data['spec']:
            policy_data['spec']['egress'] = [{}]
        
        if L7allowAll:
            add_L7_allowAll(policy_data)

        ordered_policy_data = reorder_policy(policy_data)

        filename = os.path.join(directory, f"{policy_name}.yaml")

        with open(filename, 'w') as file:
            yaml.dump(ordered_policy_data, file, default_flow_style=False, sort_keys=False)
            logging.info(f"Policy written to {filename}")
    
    json_data = json.dumps({"patterns": patternMatches}, indent=4, sort_keys=True)
    with open('report.json', 'w') as file:
        file.write(json_data)


def reorder_policy(policy):
    spec = policy.get('spec', {})
    ordered_spec = {}

    if 'endpointSelector' in spec:
        ordered_spec['endpointSelector'] = spec['endpointSelector']

    for direction in ['ingress', 'egress']:
        if direction in spec:
            ordered_rules = []
            for rule in spec[direction]:
                if 'toEntities' in rule or 'fromEntities' in rule:
                    ordered_rules.append(rule)
            for rule in spec[direction]:
                if 'toEntities' not in rule and 'fromEntities' not in rule:
                    ordered_rules.append(rule)
            ordered_spec[direction] = ordered_rules
    policy['spec'] = ordered_spec
    return policy