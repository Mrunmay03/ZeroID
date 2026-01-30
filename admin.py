"""
Certificate Management System - Admin Interface
Django admin configuration
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .backend.certificates.models import (
    User, 
    Certificate, 
    VerificationLog, 
    RevocationRecord, 
    AuditLog,
    BlockchainTransaction
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom user admin"""
    
    list_display = ['username', 'email', 'role', 'organization', 'wallet_address', 'is_active']
    list_filter = ['role', 'is_active', 'is_staff']
    search_fields = ['username', 'email', 'organization', 'wallet_address']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('role', 'phone', 'organization', 'wallet_address')
        }),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('role', 'phone', 'organization', 'wallet_address')
        }),
    )


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    """Certificate admin"""
    
    list_display = ['certificate_id', 'title', 'holder_name', 'issuer', 'status', 'issued_date']
    list_filter = ['status', 'issued_date', 'blockchain_network']
    search_fields = ['certificate_id', 'title', 'holder_name', 'issuer__username']
    readonly_fields = ['id', 'certificate_id', 'hash_value', 'issued_date', 'modified_date']
    
    fieldsets = (
        ('Certificate Information', {
            'fields': ('certificate_id', 'title', 'holder_name', 'description')
        }),
        ('Relationships', {
            'fields': ('issuer', 'holder')
        }),
        ('File & Security', {
            'fields': ('certificate_file', 'hash_value')
        }),
        ('Blockchain', {
            'fields': ('blockchain_tx_hash', 'blockchain_network', 'smart_contract_address'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('status', 'expiry_date')
        }),
        ('Timestamps', {
            'fields': ('issued_date', 'modified_date'),
            'classes': ('collapse',)
        }),
    )


@admin.register(VerificationLog)
class VerificationLogAdmin(admin.ModelAdmin):
    """Verification log admin"""
    
    list_display = ['certificate_id_checked', 'result', 'verifier', 'hash_match', 'verified_at']
    list_filter = ['result', 'hash_match', 'blockchain_verified', 'verified_at']
    search_fields = ['certificate_id_checked', 'verifier__username']
    readonly_fields = ['verified_at']
    
    fieldsets = (
        ('Verification Details', {
            'fields': ('certificate', 'certificate_id_checked', 'verifier', 'result', 'hash_match')
        }),
        ('Blockchain', {
            'fields': ('blockchain_verified', 'blockchain_verification_data'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('verified_at', 'ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
    )


@admin.register(RevocationRecord)
class RevocationRecordAdmin(admin.ModelAdmin):
    """Revocation record admin"""
    
    list_display = ['get_certificate_id', 'revoked_by', 'revoked_at']
    list_filter = ['revoked_at']
    search_fields = ['certificate__certificate_id', 'revoked_by__username', 'reason']
    readonly_fields = ['revoked_at']
    
    def get_certificate_id(self, obj):
        return obj.certificate.certificate_id
    get_certificate_id.short_description = 'Certificate ID'
    
    fieldsets = (
        ('Revocation Details', {
            'fields': ('certificate', 'revoked_by', 'reason', 'revoked_at')
        }),
        ('Blockchain', {
            'fields': ('blockchain_tx_hash',),
            'classes': ('collapse',)
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Audit log admin"""
    
    list_display = ['action', 'user', 'get_certificate_id', 'timestamp', 'blockchain_logged']
    list_filter = ['action', 'blockchain_logged', 'timestamp']
    search_fields = ['action', 'user__username', 'certificate__certificate_id']
    readonly_fields = ['timestamp']
    
    def get_certificate_id(self, obj):
        return obj.certificate.certificate_id if obj.certificate else '-'
    get_certificate_id.short_description = 'Certificate ID'
    
    fieldsets = (
        ('Action Details', {
            'fields': ('action', 'user', 'certificate', 'details')
        }),
        ('Metadata', {
            'fields': ('timestamp', 'ip_address', 'user_agent', 'blockchain_logged'),
            'classes': ('collapse',)
        }),
    )


@admin.register(BlockchainTransaction)
class BlockchainTransactionAdmin(admin.ModelAdmin):
    """Blockchain transaction admin"""
    
    list_display = ['get_certificate_id', 'transaction_type', 'tx_hash_short', 'network', 'status', 'created_at']
    list_filter = ['transaction_type', 'network', 'status', 'created_at']
    search_fields = ['certificate__certificate_id', 'tx_hash']
    readonly_fields = ['created_at', 'confirmed_at']
    
    def get_certificate_id(self, obj):
        return obj.certificate.certificate_id
    get_certificate_id.short_description = 'Certificate ID'
    
    def tx_hash_short(self, obj):
        return f"{obj.tx_hash[:10]}..." if obj.tx_hash else '-'
    tx_hash_short.short_description = 'TX Hash'
    
    fieldsets = (
        ('Transaction Details', {
            'fields': ('certificate', 'transaction_type', 'tx_hash', 'status')
        }),
        ('Blockchain Info', {
            'fields': ('network', 'block_number', 'contract_address')
        }),
        ('Gas Info', {
            'fields': ('gas_used', 'gas_price'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('error_message', 'created_at', 'confirmed_at'),
            'classes': ('collapse',)
        }),
    )
