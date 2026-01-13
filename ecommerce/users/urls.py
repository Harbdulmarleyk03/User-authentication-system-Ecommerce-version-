from django.urls import path 
from .views import RegisterAPIView, ChangePasswordView, LoginAPIView, UserProfileAPIView, LogoutAPIView, VerifyEmailView, PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(),  name='logout'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path("password-reset/request/", PasswordResetRequestView.as_view(), name='password-reset-request'),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]