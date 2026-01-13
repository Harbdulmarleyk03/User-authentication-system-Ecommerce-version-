from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _ 
from django.conf import settings
from django.utils import timezone
import uuid 

class CustomUser(AbstractUser):
    username = models.CharField(max_length=80, blank=True, null=True)
    email = models.EmailField(_('email_address'), unique=True)
    phone = models.CharField(max_length=20, blank=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, null=True, blank=True)
    verification_token_created_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    class Meta:
        db_table = 'users'

    def __str__(self):
        return "{}".format(self.email)
    
    def get_roles(self):
        return Role.objects.filter(
            user_assignments__user=self,
            user_assignments__is_active=True,
            is_active=True
        ).distinct()

    def get_permissions(self):
        return Permission.objects.filter(
            roles__user_assignments__user=self,
            roles__user_assignments__is_active=True,
            roles__is_active=True
        ).distinct()

    def has_permission(self, codename):
        return self.get_permissions().filter(codename=codename).exists()

    def has_role(self, role_name):
        return self.get_roles().filter(name=role_name).exists()

    def is_admin(self):
        return self.has_role(Role.ADMIN)

    def is_seller(self):
        return self.has_role(Role.SELLER)

    def is_customer(self):
        return self.has_role(Role.CUSTOMER)

class Profile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='user_profile')
    avatar = models.ImageField(upload_to='profile_img')

    def __str__(self):
        return self.user.username 

class PasswordResetToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_reset_token')
    token_hash = models.CharField(max_length=128, unique=True)
    used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.expires_at



class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True, db_index=True)
    description = models.TextField(blank=True)
    resource = models.CharField(max_length=50)
    action = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'permissions'
        ordering = ['resource', 'action']
        unique_together = ['resource', 'action']

    def __str__(self):
        return f"{self.codename}"

    def save(self, *args, **kwargs):
        if not self.codename:
            self.codename = f"{self.resource}_{self.action}".lower()
        super().save(*args, **kwargs)

class Role(models.Model):
    ADMIN = 'Admin'
    SELLER = 'Seller'
    CUSTOMER = 'Customer'
    
    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (SELLER, 'Seller'),
        (CUSTOMER, 'Customer'),
    ]
    
    name = models.CharField(max_length=100, unique=True, choices=ROLE_CHOICES)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, related_name='roles', blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'roles'
        ordering = ['name']

    def __str__(self):
        return self.name

class UserRole(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_assignments')
    assigned_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='role_assignments_made')
    assigned_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'user_roles'
        unique_together = ['user', 'role']
        ordering = ['-assigned_at']

    def __str__(self):
        return f"{self.user.email} - {self.role.name}"
