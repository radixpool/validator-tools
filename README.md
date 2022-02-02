```
Usage: unregister.py [OPTIONS]

  Unregisters a Validator node using a Keystore file and password

Options:
  -f, --filename FILE             Keystore filename  [default: node-
                                  keystore.ks]
  -p, --password TEXT             Keystore password. Will be prompted if not
                                  provided as an option.
  -n, --network [mainnet|stokenet]
                                  Radix Network  [default: mainnet]
  -d, --dry-run                   Do not make any changes
  -v, --verbose                   Show details of api calls and responses
  --yes                           Confirm the action without prompting.
  -h, --help                      Show this message and exit.
```

### Example Usage

Using defaults:

* Network:  mainnet
* Filename: node-keystore.ks
* Prompt for password
```bash
unregister.py

# Keystore password:
# Are you sure you want to unregister the validator? [y/N]:
# Validator Address: tv1q...
# Validator Wallet:  tdx1q...
# Building Request
# Signing Request
# Submitting Request
# Success
```

Dry-run on Stokenet with no prompts:
```bash
unregister.py -n stokenet -f ~/testkey.ks -p "secretpassword" -d --yes

# Validator Address: tv1q...
# Validator Wallet:  tdx1q...
# Building Request
# Signing Request
# Not Submitting Request [Dry Run]

```
