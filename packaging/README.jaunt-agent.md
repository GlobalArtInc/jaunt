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

The package also installs `/usr/bin/jaunt-host-users`, the root helper that
creates the account of a user at the first login. It does nothing until you
add `--create-accounts` to the install command above:

    jaunt-agent install --create-accounts --binary /usr/bin/jaunt-agent

Run that command again after every upgrade of the package, so that the
installer checks the helper and its directories again. `jaunt-agent uninstall`
keeps the accounts that were created; `jaunt-host-users list` shows them.

After an upgrade of the package, restart the service yourself:

    systemctl restart jaunt-agent

Before `apt remove` run `jaunt-agent uninstall` (add `--purge` to delete the
stored identity); the package does not stop the service or remove the sshd
drop-in.

Documentation: https://github.com/GlobalArtInc/jaunt/blob/main/docs/install.md
