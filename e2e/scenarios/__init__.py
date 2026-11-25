from . import enrol, expiry, forwarding, logins, nodes, policy, revocation, ssh, transfers

SCENARIOS = [
    ("enrol", enrol.run),
    ("logins", logins.run),
    ("ssh", ssh.run),
    ("transfers", transfers.run),
    ("forwarding", forwarding.run),
    ("policy", policy.run),
    ("revocation", revocation.run),
    ("nodes", nodes.run),
    ("expiry", expiry.run),
]
