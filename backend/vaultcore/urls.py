# from django.urls import path
# from . import views
# from django.contrib.auth import views as auth_views
# from .views import CustomLoginView, VerifyOTPView, setup_2fa

# app_name = 'vaultcore'

# urlpatterns = [
#     # Main features
#     path('add/', views.add_credential, name='add_credential'),
#     path('dashboard/', views.dashboard, name='dashboard'),
#     #path('login/', CustomLoginView.as_view(), name='login'),
#     path('activity/', views.activity_log, name='activity_log'),
#     path('accounts/profile/', views.profile_view, name='profile'),

#     # ✅ 2FA Setup + Verification Routes
#     path('setup-2fa/', views.setup_2fa, name='setup_2fa'),
#     path('verify-token/', VerifyOTPView.as_view(), name='verify_token'),

#     # Password reset
#     path('reset_password/', auth_views.PasswordResetView.as_view(), name='reset_password'),
#     path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
#     path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
#     path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
# ]

from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .views import CustomLoginView, VerifyOTPView, setup_2fa, logout_view
from django.contrib.auth.views import LoginView

app_name = 'vaultcore'

urlpatterns = [
    # Main features
    path('dashboard/', views.dashboard, name='dashboard'),
    path('add/', views.add_credential, name='add_credential'),
    path('login/', CustomLoginView.as_view(), name='login'),  # <--- Uncomment this
    path('account/login/', CustomLoginView.as_view(), name='login'),
    path('register/', views.register_view, name='register'),  # <--- Add this
    path('activity/', views.activity_log, name='activity_log'),
    path('accounts/profile/', views.profile_view, name='profile'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.home_view, name='home'),
    path('edit/<int:credential_id>/', views.edit_credential, name='edit_credential'),
    path('delete/<int:credential_id>/', views.delete_credential, name='delete_credential'),

    # 2FA Setup + Verification Routes
    path('setup-2fa/', views.setup_2fa, name='setup_2fa'),
    #path('verify-token/', VerifyOTPView.as_view(), name='verify_token'),

    # Password reset
    path('reset_password/', auth_views.PasswordResetView.as_view(), name='reset_password'),
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('reset-password-form/', views.custom_password_reset, name='reset_password_form'),

    path('custom-reset/', views.request_reset_start, name='custom_reset'),
    path('verify-otp/', views.verify_existing_otp, name='verify_existing_otp'),
    path('setup-2fa-reset/', views.setup_2fa_reset, name='setup_2fa_reset'),
    path('set-password/', views.custom_password_reset, name='custom_password_reset'),
    path('enter-secondary/', views.enter_secondary_identifier, name='enter_secondary'),

]
