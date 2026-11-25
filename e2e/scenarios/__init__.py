from . import enrol, expiry, forwarding, logins, nodes, policy, revocation, rotation_audit, rotation_force, rotation_host, rotation_setup, rotation_user, ssh, transfers

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

ROTATION_SCENARIOS = [
    ("rotation_setup", rotation_setup.run),
    ("rotation_user", rotation_user.run),
    ("rotation_host", rotation_host.run),
    ("rotation_force", rotation_force.run),
    ("rotation_audit", rotation_audit.run),
]
