"""
Certificate Management System - URL Configuration
Clean REST API routes
"""

# certificates/admin.py
# from django.contrib import admin
# from .models import Certificate, AuditLog
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

# admin.site.register(Certificate)
# admin.site.register(AuditLog)

from certificates.views import (
    # Authentication
    UserRegistrationView,
    UserLoginView,
    UserLogoutView,
    
    # Certificates
    CertificateViewSet,
    
    # Verification
    VerificationViewSet,
    VerifyCertificateView,
    
    # Revocation
    RevocationViewSet,
    RevokeCertificateView,
    
    # Audit
    AuditLogViewSet,
    
    # Blockchain
    BlockchainTransactionViewSet,
    BlockchainSyncView,
    
    # Dashboard
    DashboardStatsView,
)

# Router for ViewSets
router = DefaultRouter()
router.register(r'certificates', CertificateViewSet, basename='certificate')
router.register(r'verifications', VerificationViewSet, basename='verification')
router.register(r'revocations', RevocationViewSet, basename='revocation')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')
router.register(r'blockchain-transactions', BlockchainTransactionViewSet, basename='blockchain-transaction')

urlpatterns = [

    path('admin/', admin.site.urls),
    # Authentication endpoints
    path('auth/register/', UserRegistrationView.as_view(), name='register'),
    path('auth/login/', UserLoginView.as_view(), name='login'),
    path('auth/logout/', UserLogoutView.as_view(), name='logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Verification endpoint (public)
    path('verify/', VerifyCertificateView.as_view(), name='verify-certificate'),
    
    # Revocation endpoint
    path('revoke/', RevokeCertificateView.as_view(), name='revoke-certificate'),
    
    # Blockchain sync endpoint
    path('blockchain/sync/', BlockchainSyncView.as_view(), name='blockchain-sync'),
    
    # Dashboard
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    
    # Include router URLs
    path('', include(router.urls)),
]
