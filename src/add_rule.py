def add_L3L4_rule(policies, policy_id, new_rule, is_ingress, is_world):
    rule_key = "ingress" if is_ingress else "egress"
    policy = policies.get(policy_id)

    if "spec" not in policy:
        policy["spec"] = {}
    if rule_key not in policy["spec"]:
        policy["spec"][rule_key] = []

    if is_world:
        endpoints_key = "fromEntities" if is_ingress else "toEntities"
    else:
        endpoints_key = "fromEndpoints" if is_ingress else "toEndpoints"

    if is_world:
        new_entity = new_rule.get(endpoints_key)
    else:
        new_labels = new_rule[endpoints_key][0].get("matchLabels", {}) if endpoints_key in new_rule else {}
    new_ports = new_rule.get("toPorts", [])

    existing_rule_found = False
    for rule in policy["spec"][rule_key]:
        if is_world:
            if endpoints_key in rule and new_entity == rule.get(endpoints_key):
                existing_rule_found = True
        else:
            if endpoints_key in rule and rule[endpoints_key][0].get("matchLabels", {}) == new_labels:
                existing_rule_found = True
        
        if existing_rule_found:
            existing_ports = rule.get("toPorts", [])
            for new_port in new_ports:
                if new_port not in existing_ports:
                    rule["toPorts"] = existing_ports + [new_port]
            break

    if not existing_rule_found:
        policy["spec"][rule_key].append(new_rule)

def add_L7_rule(policies, policy_id, is_ingress, port_number, protocol, l7_rules, is_world):
    policy = policies[policy_id]
    rule_key = "ingress" if is_ingress else "egress"
    direction_rules = policy['spec'].setdefault(rule_key, [])

    entity_key = 'toEntities' if rule_key == 'egress' else 'fromEntities'
    endpoint_key = 'toEndpoints' if rule_key == 'egress' else 'fromEndpoints'

    for rule in direction_rules:
        if is_world:
            if entity_key in rule and 'world' in rule[entity_key]:
                target_rule = rule
        else:
            if endpoint_key in rule:
                target_rule = rule

    to_ports = target_rule.setdefault('toPorts', [])
    for port_entry in to_ports:
        if port_entry['ports'][0]['port'] == str(port_number):
            port_rules = port_entry.setdefault('rules', {})
            if protocol not in port_rules:
                port_rules[protocol] = []
            if l7_rules not in port_rules[protocol]:
                port_rules[protocol].append(l7_rules)

def add_L7_allowAll(policy_data):
    port_protocol_map = {
        '80': 'http',
        '8080': 'http',
        '443': 'http',
        '8443': 'http',
        '50051': 'http',
        '9555': 'http',
        '7000': 'http',
        '7070': 'http',
        # '53': 'dns',
        '9092': 'kafka',
        '9093': 'kafka'
    }

    for direction in ['ingress', 'egress']:
        if direction in policy_data['spec']:
            for rule in policy_data['spec'][direction]:
                if 'toPorts' in rule:
                    for port_entry in rule['toPorts']:
                        for port in port_entry.get('ports', []):
                            port_number = port.get('port')
                            protocol = port_protocol_map.get(port_number)
                            if protocol:
                                port_entry['rules'] = {protocol: [{}]}