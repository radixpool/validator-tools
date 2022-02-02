import click
import bech32
import ecdsa
import hashlib
import requests
import json

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
# from ecdsa.curves import SECP256k1
from ecdsa.util import sigencode_der


def abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-f', '--filename', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
              default='node-keystore.ks', show_default=True,
              help='Keystore filename')
@click.option('-p', '--password', prompt='Keystore password', hide_input=True, help='Keystore password. Will be prompted if not provided as an option.')
@click.option('-n', '--network', default='mainnet', type=click.Choice(['mainnet', 'stokenet'], case_sensitive=False),
              show_default=True, help='Radix Network')
@click.option('-d', '--dry-run', is_flag=True, help='Do not make any changes')
@click.option('-v', '--verbose', is_flag=True, help='Show details of api calls and responses')
@click.confirmation_option(prompt="Are you sure you want to unregister the validator?")
def main(filename, password, network, dry_run, verbose):
    """Unregisters a Validator node using a Keystore file and password"""

    wallet_hrp = 'rdx' if network == 'mainnet' else 'tdx'
    validator_hrp = 'rv' if network == 'mainnet' else 'tv'

    if verbose:
        print("Keystore filename:", filename)
        print("Network:", network)
        print("Dry run?", dry_run)
        print("Wallet HRP:", wallet_hrp)
        print("Validator HRP:", validator_hrp)

    with open(filename, 'rb') as f:
        private_key, certificate, additional_certificated = pkcs12.load_key_and_certificates(f.read(),
                                                                                             str.encode(password),
                                                                                             default_backend())
    # Extract the unencrypted Private Key bytes
    private_key_bytes = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

    # Convert into Elliptic Curve Digital Signature Algorithm (ecdsa) private key object
    private_key = ecdsa.SigningKey.from_der(private_key_bytes, hashfunc=hashlib.sha256)

    # Derive public key from private key
    verifying_key = private_key.get_verifying_key()

    # Convert public key into compressed format so that we can generate the Validator Address
    public_key_compressed_bytes = verifying_key.to_string("compressed")
    public_key_compressed_bytes_hex = public_key_compressed_bytes.hex()

    # Generate Validator Address from the Compressed Public Key
    public_key_bytes5 = bech32.convertbits(public_key_compressed_bytes, 8, 5)
    validator_address = bech32.bech32_encode(validator_hrp, public_key_bytes5)
    print("Validator Address:", validator_address)

    # Convert Compressed Public Key into a Radix Engine Address
    readdr_bytes = b"\x04" + public_key_compressed_bytes

    # Convert Radix Engine Address into Validator Wallet Address
    readdr_bytes5 = bech32.convertbits(readdr_bytes, 8, 5)
    validator_wallet_address = bech32.bech32_encode(wallet_hrp, readdr_bytes5)
    print("Validator Wallet: ", validator_wallet_address)

    # Build Unregister Transaction
    data = f"""
        {{
          "jsonrpc": "2.0",
          "method": "construction.build_transaction",
          "params": {{
              "actions": [
                  {{
                      "type": "UnregisterValidator",
                      "validator": "{validator_address}"
                  }}
              ],
              "feePayer": "{validator_wallet_address}"
          }},
          "id": 1
      }}
    """

    if verbose:
        print("Build Transaction Request: \n", data)

    req = requests.Request('POST', 'https://' + network + '.radixdlt.com/construction', data=data)
    # req = requests.Request('POST', 'https://' + network + '.radixdlt.com/transaction/build', data=data)
    prepared = req.prepare()
    prepared.headers['Content-Type'] = 'application/json'
    # prepared.headers['X-Radixdlt-Target-Gw-Api'] = '1.0.2'
    s = requests.Session()

    # Send Request to Unregister Validator
    click.secho('Building Request', fg='green')
    resp = s.send(prepared)

    # Get JSON Response
    resp_json = resp.json()

    if verbose:
        print("Build Transaction Response: \n", json.dumps(resp_json, indent=3))

    # Extract fields from JSON Response
    blob = resp_json['result']['transaction']['blob']
    blob_to_sign = resp_json['result']['transaction']['hashOfBlobToSign']

    click.secho('Signing Request', fg='green')

    # Sign the blob_to_sign with the Keystore Private Key and convert to DER format
    signature_der = private_key.sign_digest(bytearray.fromhex(blob_to_sign), sigencode=sigencode_der).hex()

    # Finalize Transaction
    data = f"""
        {{
          "jsonrpc": "2.0",
          "method": "construction.finalize_transaction",
          "params": {{
            "blob": "{blob}",
            "signatureDER": "{signature_der}",
            "publicKeyOfSigner": "{public_key_compressed_bytes_hex}",
            "immediateSubmit": true
          }},
          "id": 1
      }}
    """

    if verbose:
        print("Finalize Transaction Request \n: ", data)

    if dry_run:
        click.secho('Not Submitting Request [Dry Run]', fg='yellow')
    else:
        click.secho('Submitting Request', fg='green')

        req = requests.Request('POST', 'https://' + network + '.radixdlt.com/construction', data=data)
        prepared = req.prepare()
        prepared.headers['Content-Type'] = 'application/json'
        s = requests.Session()

        # Send Request to Unregister Validator
        resp = s.send(prepared)

        # Get JSON Response
        resp_json = resp.json()

        if verbose:
          print("Finalize Transaction Response: \n", json.dumps(resp_json, indent=3))

        click.secho('Success', fg='green')


if __name__ == "__main__":
    main()
