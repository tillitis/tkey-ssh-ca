# A simple SSH Certificate Authority

Current state: **Proof of concept**.

A small SSH server that generates SSH user certs on demand over an SSH
connection.

You connect to the CA with SSH, using your SSH agent to authenticate,
possibly using the tkey-ssh-agent to talk to a [Tillitis
TKey](https://tillitis.se/). If successful, you get a cert back that
you can pipe or paste into a file. Use it like this:

```
$ ssh -p 2222 user@localhost > cert.pub
```

The cert will be valid and limited to the user name you use here. All
user names are accepted if your public key is in the list of
authorized keys.

You can then use the certificate to login with SSH to servers which
trust the same CA pubkey:

```
ssh -i cert.pub user@some-ssh-server
```

The CA can also sign the cert using a TKey. The connection with the
the TKey happens transparently through the use of
[tkey-ssh-agent](https://github.com/tillitis/tkey-ssh-agent/) running
both on the CA server and your machine.

*Nota bene*: The TKey is (so far) *not required* to use this program.

## Rationale

- System owners don't want to manage individual public keys on the
  servers or embedded systems.

- Instead, they only install a trusted CA public key on all servers.

- The system owner hands out certs to all trusted users who want to
  use the servers.

- The certs can be time-limited, perhaps even very limited, like an
  hour.

- We want to show that you can use the Tillitis TKey both as the CA's
  private key and as the user's long-lived identity.

- In this scenario with tkey-ssh-ca the system owner can hand out
  TKeys to the users, record the public key (with no or a known USS)
  as allowed users.

- The users can then request short-lived certs at will.

## Setup

You need to generate a host key pair to identify the host running the
ssh-ca:

$ ssh-keygen -t ed25519

Call it `host_ed25519`.

You need the
[tkey-ssh-agent](https://github.com/tillitis/tkey-ssh-agent/]
installed and running on both the CA server and the user's machine.

Make sure the `ssh-keygen` command is available.

If you don't want to touch the TKey every time the CA generates a cert
look into the documentation to compile the tkey-ssh-agent and the
corresponding
[tkey-device-signer](https://github.com/tillitis/tkey-device-signer)
without the touch requirement.

After starting the tkey-ssh-agent (possibly with a USS), get the
public key of your CA's key pair, typically with `ssh-add -L`. Place
the key in a file called `ca_key.pub` in the ssh-ca directory.

Note that if you're trying this out on the same machine you can use
the same pubkey both for the CA and the user. You will then be
expected to touch your TKey twice: first when authentication to
tkey-ssh-ca, then to sign the new cert.

If you want to, you can allow anyone to request a certificate. If you
want to allow this, start the `tkey-ssh-ca` with the `--insecure`
flag. NOTE WELL: Anyone who requests a cert and presents a public key
will get a cert!

If, on the other hand, you want to allow just a list of approved
identities to request a cert: Get the users' public keys and place
them in `authorized_keys` in the tkey-ssh-ca directory, one per line
in this format:

```
ssh-ed25519 AAAA... key-id@domain
```

Insert the TKey in the CA server.

Start the CA server:

```
$ ./tkey-ssh-ca
```

## Development

tkey-ssh-ca currently depends the tkey-ssh-agent running on the CA
server, too. This might change. It might, instead, connect to the TKey
directly.
