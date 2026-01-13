import uuid
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
import secrets
import hashlib
from datetime import timedelta
from django.utils import timezone
from .models import PasswordResetToken
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction


User = get_user_model()

def generate_verification_token():
    return str(uuid.uuid4())

def send_verification_email(user, request):
    verification_url = request.build_absolute_uri(
        reverse('verify-email', kwargs={'token': user.verification_token})
    )

    subject = "Verify Your Email Address"
    message = f"Click the link to verify your email: {verification_url}"

    send_mail(
        subject,
        message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[user.email],
        fail_silently=False,
    )

def generate_reset_token():
    return secrets.token_urlsafe(32)

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def token_expiry(minutes=30):
    return timezone.now() + timedelta(minutes=minutes)

def create_password_reset(email: str, expiry_minutes=30):
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return 

    raw_token = generate_reset_token()

    PasswordResetToken.objects.create(
        user=user,
        token_hash=hash_token(raw_token),
        expires_at= timezone.now() + timedelta(minutes=expiry_minutes)
    )
    send_mail(
        subject="Password Reset",
        message=f"Your reset token: {raw_token}",
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[user.email],
        fail_silently=True,
        )


@transaction.atomic
def confirm_password_reset(token: str, new_password: str):
    token_hash = hash_token(token)

    try:
        reset_token = PasswordResetToken.objects.select_for_update().get(
            token_hash=token_hash,
            used=False
        )
    except PasswordResetToken.DoesNotExist:
        raise ValidationError("Invalid or expired token")

    if reset_token.is_expired():
        raise ValidationError("Token expired")

    user = reset_token.user
    user.set_password(new_password)
    user.save()

    reset_token.used = True
    reset_token.save()
