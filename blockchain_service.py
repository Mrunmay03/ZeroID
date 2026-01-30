"""
Certificate Management System - Blockchain Service
Web3 integration for Ethereum/Polygon blockchain
Ready for smart contract integration
"""

from web3 import Web3
from django.conf import settings
import json
from typing import Optional, Dict, Any
from datetime import datetime


class BlockchainService:
    """
    Service class for blockchain integration
    Handles certificate issuance, verification, and revocation on blockchain
    """
    
    def __init__(self, network: str = None):
        """Initialize Web3 connection"""
        self.network = network or settings.BLOCKCHAIN_SETTINGS['DEFAULT_NETWORK']
        self.network_config = settings.BLOCKCHAIN_SETTINGS['NETWORKS'][self.network]
        
        # Initialize Web3
        self.w3 = Web3(Web3.HTTPProvider(self.network_config['RPC_URL']))
        
        # Contract address and ABI (to be set after contract deployment)
        self.contract_address = settings.BLOCKCHAIN_SETTINGS.get('CONTRACT_ADDRESS')
        self.contract_abi = self._load_contract_abi()
        
        # Initialize contract if address is set
        self.contract = None
        if self.contract_address and self.contract_abi:
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=self.contract_abi
            )
    
    def _load_contract_abi(self) -> Optional[list]:
        """Load smart contract ABI from file"""
        # TODO: Load from actual ABI file
        # Example ABI structure for certificate contract
        return [
            {
                "inputs": [
                    {"name": "certificateId", "type": "string"},
                    {"name": "hash", "type": "bytes32"},
                    {"name": "holderAddress", "type": "address"}
                ],
                "name": "issueCertificate",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "certificateId", "type": "string"}],
                "name": "verifyCertificate",
                "outputs": [
                    {"name": "exists", "type": "bool"},
                    {"name": "hash", "type": "bytes32"},
                    {"name": "isRevoked", "type": "bool"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "certificateId", "type": "string"}],
                "name": "revokeCertificate",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]
    
    def is_connected(self) -> bool:
        """Check if connected to blockchain network"""
        return self.w3.is_connected()
    
    def get_account(self) -> str:
        """Get account address from private key"""
        private_key = settings.BLOCKCHAIN_SETTINGS.get('PRIVATE_KEY')
        if not private_key:
            raise ValueError("Blockchain private key not configured")
        
        account = self.w3.eth.account.from_key(private_key)
        return account.address
    
    def issue_certificate_on_chain(
        self, 
        certificate_id: str, 
        hash_value: str, 
        holder_address: str
    ) -> Dict[str, Any]:
        """
        Issue certificate on blockchain
        
        Args:
            certificate_id: Unique certificate identifier
            hash_value: SHA-256 hash of certificate
            holder_address: Wallet address of certificate holder
        
        Returns:
            Dictionary with transaction details
        """
        if not self.contract:
            raise ValueError("Smart contract not initialized")
        
        try:
            # Prepare transaction
            private_key = settings.BLOCKCHAIN_SETTINGS.get('PRIVATE_KEY')
            account = self.w3.eth.account.from_key(private_key)
            
            # Convert hash to bytes32
            hash_bytes = Web3.to_bytes(hexstr=hash_value)
            
            # Build transaction
            transaction = self.contract.functions.issueCertificate(
                certificate_id,
                hash_bytes,
                Web3.to_checksum_address(holder_address)
            ).build_transaction({
                'from': account.address,
                'nonce': self.w3.eth.get_transaction_count(account.address),
                'gas': settings.BLOCKCHAIN_SETTINGS['GAS_LIMIT'],
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.network_config['CHAIN_ID']
            })
            
            # Sign transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for transaction receipt
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'block_number': tx_receipt['blockNumber'],
                'gas_used': tx_receipt['gasUsed'],
                'status': tx_receipt['status']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_certificate_on_chain(self, certificate_id: str) -> Dict[str, Any]:
        """
        Verify certificate on blockchain
        
        Args:
            certificate_id: Certificate identifier to verify
        
        Returns:
            Dictionary with verification results
        """
        if not self.contract:
            raise ValueError("Smart contract not initialized")
        
        try:
            # Call contract view function
            result = self.contract.functions.verifyCertificate(certificate_id).call()
            
            exists, hash_bytes, is_revoked = result
            
            return {
                'success': True,
                'exists': exists,
                'hash': hash_bytes.hex() if exists else None,
                'is_revoked': is_revoked,
                'verified_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def revoke_certificate_on_chain(self, certificate_id: str) -> Dict[str, Any]:
        """
        Revoke certificate on blockchain
        
        Args:
            certificate_id: Certificate identifier to revoke
        
        Returns:
            Dictionary with transaction details
        """
        if not self.contract:
            raise ValueError("Smart contract not initialized")
        
        try:
            # Prepare transaction
            private_key = settings.BLOCKCHAIN_SETTINGS.get('PRIVATE_KEY')
            account = self.w3.eth.account.from_key(private_key)
            
            # Build transaction
            transaction = self.contract.functions.revokeCertificate(
                certificate_id
            ).build_transaction({
                'from': account.address,
                'nonce': self.w3.eth.get_transaction_count(account.address),
                'gas': settings.BLOCKCHAIN_SETTINGS['GAS_LIMIT'],
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.network_config['CHAIN_ID']
            })
            
            # Sign transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for transaction receipt
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'block_number': tx_receipt['blockNumber'],
                'gas_used': tx_receipt['gasUsed'],
                'status': tx_receipt['status']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_transaction_status(self, tx_hash: str) -> Dict[str, Any]:
        """
        Get status of a blockchain transaction
        
        Args:
            tx_hash: Transaction hash
        
        Returns:
            Dictionary with transaction status
        """
        try:
            tx_receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            return {
                'success': True,
                'status': 'confirmed' if tx_receipt['status'] == 1 else 'failed',
                'block_number': tx_receipt['blockNumber'],
                'gas_used': tx_receipt['gasUsed']
            }
            
        except Exception as e:
            return {
                'success': False,
                'status': 'pending',
                'error': str(e)
            }
    
    def estimate_gas(self, transaction_type: str, **kwargs) -> int:
        """
        Estimate gas for a transaction
        
        Args:
            transaction_type: 'issue', 'verify', or 'revoke'
            **kwargs: Parameters for the transaction
        
        Returns:
            Estimated gas amount
        """
        if not self.contract:
            raise ValueError("Smart contract not initialized")
        
        try:
            if transaction_type == 'issue':
                gas = self.contract.functions.issueCertificate(
                    kwargs['certificate_id'],
                    kwargs['hash_bytes'],
                    kwargs['holder_address']
                ).estimate_gas()
            
            elif transaction_type == 'revoke':
                gas = self.contract.functions.revokeCertificate(
                    kwargs['certificate_id']
                ).estimate_gas()
            
            else:
                gas = settings.BLOCKCHAIN_SETTINGS['GAS_LIMIT']
            
            return gas
            
        except Exception as e:
            return settings.BLOCKCHAIN_SETTINGS['GAS_LIMIT']


# Singleton instance
_blockchain_service = None

def get_blockchain_service(network: str = None) -> BlockchainService:
    """Get or create blockchain service instance"""
    global _blockchain_service
    
    if _blockchain_service is None or (network and _blockchain_service.network != network):
        _blockchain_service = BlockchainService(network)
    
    return _blockchain_service
