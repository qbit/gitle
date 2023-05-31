gitle
=====

Quickly stand up a git server on your Tailnet

# Running

```
$ export GITLE_FULL_ACCESS_FINGREPRINTS=/var/lib/gitle/full_access
$ export GITLE_AUTH_KEYS=/var/lib/gitle/authorized_keys
$ export GITLE_HOST_KEYS=/var/lib/gitle/host_key
$ export GITLE_REPOS=/var/lib/gitle/repos
$ gitle
```

# ENV Vars
| Name | What it does |
| ---- | ---- |
| GITLE_FULL_ACCESS_FINGREPRINTS | List of ssh public keys that can *write* repos |
| GITLE_AUTH_KEYS | List of ssh public keys that can *read* repos |
| GITLE_HOST_KEYS | SSH Host key for the server to use |
| GITLE_REPOS | Path to where `gitle` will store repositories |
