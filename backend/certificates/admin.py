from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User,
    Certificate,
    VerificationLog,
    RevocationRecord,
    AuditLog,
    BlockchainTransaction,
)

# ==========================
# CUSTOM USER ADMIN
# ==========================
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Role Information", {"fields": ("role", "phone", "organization", "wallet_address")}),
    )

    list_display = ("username", "email", "role", "is_staff", "is_active")
    list_filter = ("role", "is_staff", "is_active")


# ==========================
# CERTIFICATE ADMIN
# ==========================
@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = (
        "certificate_id",
        "title",
        "holder_name",
        "issuer",
        "status",
        "issued_date",
    )
    list_filter = ("status", "issued_date")
    search_fields = ("certificate_id", "title", "holder_name")
    readonly_fields = ("certificate_id", "hash_value")


# ==========================
# VERIFICATION LOG
# ==========================
@admin.register(VerificationLog)
class VerificationLogAdmin(admin.ModelAdmin):
    list_display = ("certificate_id_checked", "result", "hash_match", "verified_at")
    list_filter = ("result",)
    search_fields = ("certificate_id_checked",)


# ==========================
# REVOCATION RECORD
# ==========================
@admin.register(RevocationRecord)
class RevocationRecordAdmin(admin.ModelAdmin):
    list_display = ("certificate", "revoked_by", "revoked_at")
    search_fields = ("certificate__certificate_id",)


# ==========================
# AUDIT LOG
# ==========================
@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "user", "certificate", "timestamp")
    list_filter = ("action", "timestamp")


# ==========================
# BLOCKCHAIN TRANSACTIONS
# ==========================
@admin.register(BlockchainTransaction)
class BlockchainTransactionAdmin(admin.ModelAdmin):
    list_display = ("transaction_type", "tx_hash", "network", "status", "created_at")
    list_filter = ("status", "network")

