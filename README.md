# PAM module for OAuth 2.0 Device Authorization Grant

PAM module for user authentication using
[OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628).

The following instructions have been tested on Ubuntu 20.04.

## Installation

Install build dependencies.

```bash
sudo apt install libldap2-dev libpam0g-dev libcurl4-openssl-dev
```

Clone the repository, build and install the module.

```bash
make
sudo mkdir /lib/security
sudo cp pam_oauth2_device.so /lib/security/
```

Create a configuration file `/etc/pam_oauth2_device/config.json`.
See `config_template.json` (LDAP section is optional).

### Configuration options

Edit `/etc/pam_oauth2_device/config.json`.

- `qr` QR code encodes the authentication URL.
  - `show`: show (`true`, default) or hide (`false`) the QR code
  - `error_correction_level`: allowed correction levels are
    - 0 - low
    - 1 - medium
    - 2 - high
- `users` User mapping from claim configured in _username_attribute_ to the local account name.
- `usersFilePath` Path to a JSON file containing user mappings. An alternative to the `users` option
of the module configuration file.
- `oauth` configuration for the OIDC identity provider.
  - `require_mfa`: if `true` the module will modify the requests to ask
    user to perform the MFA.

### Example Configuration for sshd

Edit `/etc/pam.d/sshd`. Enable `pam_oauth2_device.so` and disable password
authentication.

```
auth required pam_oauth2_device.so /etc/pam_oauth2_device/config.json

# Standard Un*x authentication.
# @include common-auth
```

Edit `/etc/ssh/sshd_config`

```sshd-config
PasswordAuthentication no
ChallengeResponseAuthentication yes
AuthenticationMethods keyboard-interactive
UsePAM yes
```

It is also possible to combine multiple authentication methods. For example,
with `AuthenticationMethods publickey,keyboard-interactive`
both public key and interactive authentication are required.

For service users, an interactive method might not be desirable.
Specify alternative authentication methods for selected users.

```sshd-config
Match User ubuntu
  AuthenticationMethods publickey
```

Restart the service after changing the sshd configuration.

```bash
systemctl restart sshd
```

## Development

For local development it is easier to use `pamtester`.

```bash
sudo apt install pamtester
```

### Configuration

Edit `/etc/pam.d/pamtester`

```
auth required pam_oauth2_device.so
```

### Deployment

```bash
sudo cp pam_oauth2_device.so /lib/security/
# or make a symlink so you don't need to copy the file each
# time you compile the module
sudo ln -s pam_oauth2_device.so /lib/security/
```

### Testing

```bash
pamtester -v pamtester username authenticate
```

## Contributing

In this project we automatically generate releases and update the changelog
(for more information see, this
[github action](https://github.com/google-github-actions/release-please-action)).
For this reason commit messages need to follow the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification.

To improve both code quality and consistency, every commit needs to pass
linter and formatter checks. Please follow the
[Google C++ style guide](https://google.github.io/styleguide/cppguide.html).
You can use `clang-format` to automatically format your code.
Formatter can be integrated with most IDEs or used from CLI, e.g.
`clang-format --style Google -i src/pam_oauth2_device.cpp`

You can run linter (`cpplint`) locally with `cpplint src/* src/include/*`.
`cpplint` is a Python tool and can be pip installed `pip install cpplint`

Make sure that unit tests are passing, see [test/README.md](test/README.md).
Add new tests if necessary.

## Security review

The code has been reviewed for security vulnerabilities at the University of Basel and Swiss Institute of Bioinformatics by Louis Ruppert and Aurélien Cavelan.
