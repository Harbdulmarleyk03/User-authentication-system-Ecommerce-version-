from rest_framework import serializers 
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .models import Profile, PasswordResetToken, Permission, UserRole, Role
from .utils import generate_verification_token, send_verification_email
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=40)
    password1 = serializers.CharField(max_length=12, label="Password", write_only=True)
    password2 = serializers.CharField(max_length=12, label="Confirm Password", write_only=True)
    role = serializers.ChoiceField(choices=[Role.CUSTOMER, Role.SELLER], default=Role.CUSTOMER)

    extra_kwargs = {
        "password": {"write_only": True},
    }
    class Meta:
        model = User
        fields = ['id', 'email', 'password1', 'password2', 'username', 'role', 'phone']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists!")
        return value 
    
    def validate(self, attrs):
        if attrs['password1'] != attrs['password2']:
            raise serializers.ValidationError("Passwords do not match!")
        password = attrs.get('password1', '')
        if len(password) < 8:
            raise serializers.ValidationError("Password must have at least 8 characters!")
        return attrs 
    
    def create(self, validated_data):
        role_name = validated_data.pop('role', Role.CUSTOMER)
        password = validated_data.pop('password1')
        validated_data.pop('password2')
        user = User.objects.create_user(password=password, **validated_data)
        user.verification_token = generate_verification_token()
        user.save()
        role = Role.objects.get(name=role_name)
        UserRole.objects.create(user=user, role=role)
        request = self.context.get('request')
        send_verification_email(user, request)
        return user 
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=40)
    password = serializers.CharField(max_length=12, write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user 
        if not user.is_verified:
            raise AuthenticationFailed("Verify email first!")
        if not user.is_active:
            raise AuthenticationFailed('Account inactive')
        raise serializers.ValidationError("Incorrect Credentials!")
    

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=12)
    new_password = serializers.CharField(max_length=12)

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect")
        return value

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def save(self):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save()

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile 
        fields = "__all__"

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'description', 'resource', 'action']


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)
    permission_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False
    )

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'permissions', 'permission_ids', 'is_active']

    def create(self, validated_data):
        permission_ids = validated_data.pop('permission_ids', [])
        role = Role.objects.create(**validated_data)
        if permission_ids:
            role.permissions.set(permission_ids)
        return role

    def update(self, instance, validated_data):
        permission_ids = validated_data.pop('permission_ids', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if permission_ids is not None:
            instance.permissions.set(permission_ids)
        return instance

class CustomUserSerializer(serializers.ModelSerializer):
    roles = RoleSerializer(source='get_roles', many=True, read_only=True)
    permissions = PermissionSerializer(source='get_permissions', many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone', 'is_verified', 'roles', 'permissions', 'created_at']
        read_only_fields = ['created_at']

class AssignRoleSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    role_id = serializers.IntegerField()

    def validate(self, data):
        try:
            user = User.objects.get(id=data['user_id'])
            role = Role.objects.get(id=data['role_id'])
            data['user'] = user
            data['role'] = role
        except User.DoesNotExist:
            raise serializers.ValidationError('User not found')
        except Role.DoesNotExist:
            raise serializers.ValidationError('Role not found')
        return data
