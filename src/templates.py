def create_policy_template(policy_id, labels):
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": policy_id},
        "spec": {
            "endpointSelector": {"matchLabels": labels}
        }
    }

def create_rule_template(port, protocol, labels, is_ingress):
    if is_ingress:
        rule_template = {
            "fromEndpoints": [{"matchLabels": labels}],
            "toPorts": [{
                "ports": [{"port": str(port), "protocol": protocol}]
            }]
        }
    else:
        rule_template = {
            "toEndpoints": [{"matchLabels": labels}],
        }
    return rule_template

def add_dns_entry(policy):
    dns_rule = {
        "toEndpoints": [
            {
                "matchLabels": {
                    "io.kubernetes.pod.namespace": "kube-system",
                    "k8s-app": "kube-dns"
                }
            }
        ],
        "toPorts": [
            {
                "ports": [
                    {
                        "port": "53",
                        "protocol": "UDP"
                    }
                ]
            }
        ]
    }

    if 'egress' not in policy['spec']:
        return policy

    policy['spec']['egress'].append(dns_rule)
    return policy
