from django.contrib import admin
from .models import Certificate

@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "holder_name",
        "issuer",
        "issued_at",
        "is_revoked",
    )
    search_fields = ("title", "holder_name", "id")
    list_filter = ("is_revoked", "issued_at")
