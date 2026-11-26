# jaunt-agent

This package installs the Jaunt node agent and its systemd unit file. It does
not enrol the node, does not change the sshd configuration, does not create the
`jaunt` account and does not enable or start the service.

Set the node up as root, in this order (the installer refuses to run on a
node that is already enrolled):

    jaunt-agent install --dry-run --binary /usr/bin/jaunt-agent
    jaunt-agent install --binary /usr/bin/jaunt-agent
    jaunt-agent enroll --server https://<host> --name <node> --ca-pin sha256:<hash>
    systemctl start jaunt-agent

The `--binary` option is needed because the installer defaults to
`/usr/local/bin/jaunt-agent`.

After an upgrade of the package, restart the service yourself:

    systemctl restart jaunt-agent

Before `apt remove` run `jaunt-agent uninstall` (add `--purge` to delete the
stored identity); the package does not stop the service or remove the sshd
drop-in.

Documentation: https://github.com/GlobalArtInc/jaunt/blob/main/docs/install.md
