"""
URL configuration for ecommerce project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from users.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('users.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('api/roles/', RoleListCreateView.as_view(), name='role-list-create'),
    path('api/roles/<int:pk>/', RoleDetailView.as_view(), name='role-detail'),
    path('api/roles/<int:pk>/assign/', AssignRoleView.as_view(), name='role-assign'),
    path('api/roles/<int:pk>/revoke/', RevokeRoleView.as_view(), name='role-revoke'),
    
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('api/users/create/', UserCreateView.as_view(), name='user-create'),
    path('api/users/me/', CurrentUserView.as_view(), name='user-me'),
    path('api/users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),
    
    path('api/permissions/', PermissionListView.as_view(), name='permission-list'),
    path('api/permissions/<int:pk>/', PermissionDetailView.as_view(), name='permission-detail'),
]
