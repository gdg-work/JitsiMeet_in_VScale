# Quickly create a temporary Jitsi Meet (teleconferencing) server in a cloud

## Why?

You need to communicate with several people and don't need any time limits.
Or may be you want to use your own server for video conference calls.

This project uses `vscale.io` cloud service of Selectel to host a temporary
server for conference.  It deploys in 5 minutes and it can be destroyed in just one.

## How?

`vscale.io` has API very similar to OpenStack (https://developers.vds.selectel.ru/documentation/api/v1/).
Any cloud-dependency is limited to `vscale_vm.py` program.  Other customizations are made
by Ansible.

### Steps to work:

1) run `vscale_vm.py create` to create cloud VM instance.
2) `cd Ansible`
3) `ansible-playbook _master.yml --vault-password-file=<vault password file>`
4) Wait for Ansible to finish
5) Wait 5' for containers to deploy
6) Open https to your new server and enter a name for your conference call
7) `vscale_vm.py list`
8) `vscale_vm.py delete`
9) `vscale_vm.py list`
10) all clear!

### Variables in vault file:

When the soludion was made in the first time, it was an ad-hoc server for my family, so I didn't think much
about re-using by other people.  Will fix that… some time.

- `dgolub_passwd` : Password of user, who will manage Docker containers
- `dgolub_key` : SSH key of that user
- `dyndns_email` : E-Mail registered with DynDNS
- `dyndns_password` : Password on DynDNS with 'change IP address' permission

## TODO

- HTTPS not working, need to fix LetsEncrypt certificate handling or make certificate from dyno (dyndns)
- change default user name to configurable one
- re-initialize passwords in the environment file?

