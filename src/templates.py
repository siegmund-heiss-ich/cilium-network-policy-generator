def create_policy_template(policy_id, namespace, labels):
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": policy_id, "namespace": namespace},
        "spec": {
            "endpointSelector": {"matchLabels": labels}
        }
    }

def create_rule_template(port, protocol, labels, is_ingress, is_world):
    rule_key = "fromEndpoints" if is_ingress else "toEndpoints"
    rule_template = {}

    if is_world:
        entity_key = "fromEntities" if is_ingress else "toEntities"
        rule_template[entity_key] = ["world"]
    else:
        rule_template[rule_key] = [{"matchLabels": labels}]

    rule_template["toPorts"] = [{
        "ports": [{"port": str(port), "protocol": protocol}]
    }]

    return rule_template