import json
from base58 import b58encode

from solana.rpc.async_api import AsyncClient
from solana.transaction import Instruction, AccountMeta
from solana.rpc import commitment
from solana.rpc.types import Pubkey, TxOpts
from solders.keypair import Keypair
from solders import compute_budget
from solders.message import MessageV0, to_bytes_versioned
from solders.transaction import VersionedTransaction
from solders.address_lookup_table_account import AddressLookupTableAccount, AddressLookupTable
from solders.signature import Signature


class SolAccount:
    def __init__(self, sol_key):
        self.keypair = Keypair.from_base58_string(sol_key)
        self.sol_client = AsyncClient("https://api.mainnet-beta.solana.com")

    def sign_sol_message(self, message):
        message_bytes = message.encode('utf-8')
        signature = self.keypair.sign_message(message_bytes).__bytes__()
        return b58encode(signature).decode()

    async def simulate_tx(self, vtx: VersionedTransaction):
        signature = self.keypair.sign_message(to_bytes_versioned(vtx.message))
        signed_txn = VersionedTransaction.populate(vtx.message, [signature])
        sim_resp = await self.sol_client.simulate_transaction(signed_txn, commitment=commitment.Confirmed)
        return sim_resp

    async def send_tx(self, vtx: VersionedTransaction) -> str:
        signature = self.keypair.sign_message(to_bytes_versioned(vtx.message))
        signed_txn = VersionedTransaction.populate(vtx.message, [signature])

        opts = TxOpts(skip_preflight=True, preflight_commitment=commitment.Confirmed)
        result = await self.sol_client.send_transaction(txn=signed_txn, opts=opts)
        transaction_id = json.loads(result.to_json())["result"]
        return transaction_id

    async def solana_trade(self, instructions, address_lookup_table_addresses):
        ixs = [compute_budget.set_compute_unit_price(2_500_000), compute_budget.set_compute_unit_limit(200_000)]

        for instruction in instructions:
            accounts = []
            for account in instruction['keys']:
                accounts.append(
                    AccountMeta(pubkey=Pubkey.from_string(account['pubkey']), is_signer=account['isSigner'],
                                is_writable=account['isWritable'])
                )
            ist = Instruction(
                program_id=Pubkey.from_string(instruction['programId']),
                data=bytes.fromhex(instruction['data']),
                accounts=accounts
            )
            ixs.append(ist)

        multiple_pub_keys = [Pubkey.from_string(a) for a in address_lookup_table_addresses]
        multiple_account_info = await self.sol_client.get_multiple_accounts(multiple_pub_keys)

        address_table_list = [
            AddressLookupTableAccount(
                key=Pubkey.from_string(k),
                addresses=AddressLookupTable.deserialize(
                    multiple_account_info.value[i].data
                ).addresses
            )
            for i, k in enumerate(address_lookup_table_addresses)
        ]

        recent_blockhash = await self.sol_client.get_latest_blockhash(commitment=commitment.Confirmed)
        msg_v0 = MessageV0.try_compile(self.keypair.pubkey(), ixs, address_table_list,
                                       recent_blockhash.value.blockhash)
        vtx = VersionedTransaction.populate(msg_v0, [Signature.default()])

        tx_id = await self.send_tx(vtx)

        return tx_id
