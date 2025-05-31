from web3 import Web3
from eth_account.messages import encode_defunct


def get_signature(message, private_key):
    encoded_msg = encode_defunct(text=message)
    signed_msg = Web3().eth.account.sign_message(encoded_msg, private_key=private_key)
    signature = signed_msg.signature.hex()

    return signature
