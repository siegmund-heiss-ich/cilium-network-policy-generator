def add_rule(policies, policy_id, new_rule, is_ingress):
    rule_key = "ingress" if is_ingress else "egress"
    policy = policies.get(policy_id)

    if rule_key not in policy["spec"]:
        policy["spec"][rule_key] = [new_rule]

    endpoints_key = "fromEndpoints" if is_ingress else "toEndpoints"
    new_labels = new_rule[endpoints_key][0]["matchLabels"]

    new_ports = new_rule.get("toPorts", [])

    existing_rule_found = False
    for rule in policy["spec"][rule_key]:
        if endpoints_key in rule and rule[endpoints_key][0]["matchLabels"] == new_labels:
            existing_rule_found = True
            existing_ports = rule.get("toPorts", [])
            for new_port in new_ports:
                if new_port not in existing_ports:
                    rule["toPorts"] = existing_ports + [new_port]
            break

    if not existing_rule_found:
        policy["spec"][rule_key].append(new_rule)