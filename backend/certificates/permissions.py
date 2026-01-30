"""
Certificate Management System - Permissions
Role-based access control
"""

from rest_framework import permissions


class IsIssuer(permissions.BasePermission):
    """Only allow issuers"""
    
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'issuer'


class IsVerifier(permissions.BasePermission):
    """Only allow verifiers"""
    
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'verifier'


class IsHolder(permissions.BasePermission):
    """Only allow holders"""
    
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'holder'


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner
        return obj.issuer == request.user
