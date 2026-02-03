# certificates/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
router.register('certificates', CertificateViewSet, basename='certificate')
router.register('verifications', VerificationViewSet, basename='verification')
router.register('revocations', RevocationViewSet, basename='revocation')
router.register('audit-logs', AuditLogViewSet, basename='audit')
router.register('blockchain', BlockchainTransactionViewSet, basename='blockchain')

urlpatterns = [
    path('auth/register/', UserRegistrationView.as_view()),
    path('auth/login/', UserLoginView.as_view()),
    path('auth/logout/', UserLogoutView.as_view()),
    path('verify/', VerifyCertificateView.as_view()),
    path('revoke/', RevokeCertificateView.as_view()),
    path('dashboard/', DashboardStatsView.as_view()),
    path('', include(router.urls)),
]
