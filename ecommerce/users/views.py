from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from .serializers import ( RegisterSerializer, LoginSerializer, CustomUserSerializer, 
 UserProfileSerializer, PasswordResetConfirmSerializer, ChangePasswordSerializer,
 RoleSerializer, AssignRoleSerializer, PermissionSerializer)
from .models import UserRole, Role, Permission
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
import uuid
from .utils import send_verification_email, create_password_reset
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView
from .serializers import PasswordResetRequestSerializer
from django.core.exceptions import ValidationError
from .utils import confirm_password_reset
from .permissions import IsAdmin, IsOwnerOrAdmin

User = get_user_model()

class RegisterAPIView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny, ]
    throttle_scope = "register"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save(is_active=False, is_verified=False)
        user.verification_token = uuid.uuid4()
        user.save()
        send_verification_email(user, request)
        data = serializer.data
        return Response(data, status=status.HTTP_201_CREATED)
    
class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [AllowAny, ]
    throttle_scope = "email_verify"

    def get(self, request, token, *args, **kwargs):
        try:
            user = User.objects.get(verification_token=token)
            if user.is_verified:
                return Response({"message": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)
            user.is_verified=True
            user.is_active=True
            user.verification_token = None
            user.verification_token_created_at = timezone.now() 
            if (
                not user.verification_token_created_at or timezone.now() - user.verification_token_created_at > timedelta(hours=24)):
                return Response({"error": "Verification link expired"}, status=status.HTTP_400_BAD_REQUEST)
            user.save()
            return Response({"message": "Email verified successfully. You can login now."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "Invalid verification token"}, status=status.HTTP_400_BAD_REQUEST)
    
class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny,]
    throttle_scope = "login"

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        serializer = CustomUserSerializer(user)
        data = serializer.data 
        token = RefreshToken.for_user(user)
        data['tokens'] = {"refresh": str(token),
                         "access": str(token.access_token)}
        return Response(data, status=status.HTTP_200_OK)
    

class LogoutAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        try: 
            refresh_token = request.data['refresh']
            token  = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        

class PasswordResetRequestView(APIView):
    permission_classes = []
    serializer_class = PasswordResetRequestSerializer
    throttle_scope = "password_reset"

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        create_password_reset(serializer.validated_data["email"])
        return Response(
            {"detail": "If the email exists, a reset link was sent."},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    permission_classes = []
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            confirm_password_reset(
                token=serializer.validated_data["token"],
                new_password=serializer.validated_data["new_password"]
            )
        except ValidationError as e:
            return Response(
                {"detail": e.message},
                status=status.HTTP_400_BAD_REQUEST
            )
        return Response(
            {"detail": "Password reset successful"},
            status=status.HTTP_200_OK
        )
    
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated,]
    serializer_class = ChangePasswordSerializer
    throttle_scope = "change_password"

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": "Password changed successfully"},
            status=status.HTTP_200_OK
        )

class UserProfileAPIView(generics.RetrieveAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, ]

    def get_object(self):
        return self.request.user 
    
class RoleListCreateView(generics.ListCreateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, IsAdmin]


class RoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, IsAdmin]


class AssignRoleView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        serializer = AssignRoleSerializer(data={**request.data, 'role_id': role.id})
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            UserRole.objects.get_or_create(
                user=user,
                role=role,
                defaults={'assigned_by': request.user}
            )
            return Response({
                'message': f'Role {role.name} assigned to {user.email}'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RevokeRoleView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        user_id = request.data.get('user_id')
        
        try:
            user = User.objects.get(id=user_id)
            UserRole.objects.filter(user=user, role=role).update(is_active=False)
            return Response({
                'message': f'Role {role.name} revoked from {user.email}'
            })
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

class UserCreateView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = CustomUserSerializer(request.user)
        return Response(serializer.data)

class PermissionListView(generics.ListAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

class PermissionDetailView(generics.RetrieveAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, IsAdmin]