from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
#from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.views import View
from django.contrib import messages
from django.urls import reverse
from user_agents import parse as parse_ua
from django.http import HttpResponse
# ✅ ADD THIS AT THE TOP of views.py
from django.contrib.auth import get_user_model
User = get_user_model()
from django.contrib.auth.hashers import check_password
from .forms import CustomUserCreationForm, CredentialForm
from .models import Credential, ActivityLog, TOTPDevice, UserProfile
from .utils.encryption import encrypt_password, decrypt_password
from .utils.logger import log_activity
from axes.utils import reset
import pyotp, qrcode, io, base64
from django.shortcuts import render, redirect
from django.contrib.auth import login
from .forms import StrongPasswordForm

# -----------------------------
# Core Features
# -----------------------------

@login_required
def dashboard(request):
    profile = getattr(request.user, 'userprofile', None)
    if not profile or not profile.is_2fa_enabled:
        return redirect('vaultcore:setup_2fa')

    credentials = Credential.objects.filter(user=request.user)
    decrypted_credentials = [{
        'id': c.id,
        'website': c.website,
        'login_username': c.login_username,
        'password': decrypt_password(c.encrypted_password, c.iv),
        'notes': c.notes,
    } for c in credentials]

    return render(request, 'dashboard.html', {'credentials': decrypted_credentials})

def register(request):
    if request.method == 'POST':
        form = StrongPasswordForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')
    else:
        form = StrongPasswordForm()
    return render(request, 'register.html', {'form': form})

@login_required
def add_credential(request):
    if request.method == 'POST':
        form = CredentialForm(request.POST)
        if form.is_valid():
            cred = form.save(commit=False)
            encrypted, iv = encrypt_password(form.cleaned_data['plain_password'])
            cred.encrypted_password = encrypted
            cred.iv = iv
            cred.user = request.user
            cred.save()
            log_activity(request, 'add_credential')
            return redirect('vaultcore:dashboard')
    else:
        form = CredentialForm()
    return render(request, 'add_credential.html', {'form': form})

@login_required
def edit_credential(request, credential_id):
    credential = Credential.objects.get(id=credential_id, user=request.user)
    if request.method == 'POST':
        form = CredentialForm(request.POST, instance=credential)
        if form.is_valid():
            updated = form.save(commit=False)
            encrypted, iv = encrypt_password(form.cleaned_data['plain_password'])
            updated.encrypted_password = encrypted
            updated.iv = iv
            updated.save()
            log_activity(request, 'edit_credential')
            return redirect('vaultcore:dashboard')
    else:
        form = CredentialForm(instance=credential)
    return render(request, 'edit_credential.html', {'form': form})

@login_required
def delete_credential(request, credential_id):
    credential = Credential.objects.get(id=credential_id, user=request.user)
    if request.method == 'POST':
        credential.delete()
        log_activity(request, 'delete_credential')
        return redirect('vaultcore:dashboard')
    return render(request, 'confirm_delete.html', {'credential': credential})

@login_required
def activity_log(request):
    logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')
    enhanced_logs = []
    for log in logs:
        #ua = parse_ua(log.user_agent)
        device = log.device#f"{log.device.os.family} {log.device.browser.family} ({log.device.device.family})"
        enhanced_logs.append({
            'activity_type': log.activity_type,
            'ip_address': log.ip_address,
            'device': device,
            'timestamp': log.timestamp,
            #'timezone': log.timezone
        })
    return render(request, 'activity_log.html', {'logs': enhanced_logs})

def home_view(request):
    return render(request, 'home.html')

def profile_view(request):
    return HttpResponse("This is the default profile page.")

def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('vaultcore:setup_2fa')
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})

class CustomLoginView(LoginView):
    template_name = 'login.html'

    def dispatch(self, request, *args, **kwargs):
        if 'session_expired' in request.GET:
            messages.warning(request, "Your session expired. Please log in again.")
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        profile = getattr(self.request.user, 'userprofile', None)
        if profile and (not profile.is_2fa_enabled or not self.request.session.get('is_2fa_verified')):
            return reverse('vaultcore:setup_2fa')
        return reverse('vaultcore:dashboard')


def logout_view(request):
    request.session.flush()
    logout(request)
    return redirect('/')

# -----------------------------
# 2FA Setup & Verification
# -----------------------------

@login_required
def setup_2fa(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    if not profile.otp_secret:
        profile.otp_secret = pyotp.random_base32()
        profile.save()

    totp = pyotp.TOTP(profile.otp_secret)
    otp_uri = totp.provisioning_uri(name=request.user.username, issuer_name="SecureVault")
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    if request.method == 'POST':
        code = request.POST.get("otp_code")
        if totp.verify(code):
            profile.is_2fa_enabled = True
            profile.save()
            request.session['is_2fa_verified'] = True
            return redirect('vaultcore:dashboard')
        return render(request, 'vaultcore/setup_2fa.html', {'qr': qr_base64, 'error': 'Invalid code.'})

    return render(request, 'vaultcore/setup_2fa.html', {'qr': qr_base64})

class VerifyOTPView(View):
    def get(self, request):
        return render(request, 'vaultcore/verify_token.html')

    def post(self, request):
        profile = request.user.userprofile
        totp = pyotp.TOTP(profile.otp_secret)
        code = request.POST.get('otp_code')

        if totp.verify(code):
            profile.otp_verified = True
            profile.save()
            request.session['is_2fa_verified'] = True
            return redirect('vaultcore:dashboard')

        messages.error(request, 'Invalid OTP code.')
        return redirect('vaultcore:verify_token')

# -----------------------------
# Custom Password Reset Flow with 2FA
# -----------------------------

def request_reset_start(request):
    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()
        user = None

        try:
            user = User.objects.get(username=identifier)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                return render(request, 'vaultcore/forgot_password.html', {
                    'error': 'No user found with that username or email.'
                })
        request.session['identifier'] = identifier
        request.session['reset_user_id'] = user.id

        # If 2FA is already enabled
        if user.userprofile.is_2fa_enabled:
            return redirect('vaultcore:verify_existing_otp')
        else:
            # If 2FA not enabled, redirect to setup
            request.session['missing_identifier'] = identifier
            request.session['missing_type'] = 'email' if '@' in identifier else 'username'
            return redirect('vaultcore:enter_secondary')
        

    return render(request, 'vaultcore/forgot_password.html')

def verify_existing_otp(request):
    user_id = request.session.get('reset_user_id')
    if not user_id:
        return redirect('vaultcore:start_reset_password')

    user = User.objects.get(id=user_id)
    profile = user.userprofile
    totp = pyotp.TOTP(profile.otp_secret)

    if request.method == 'POST':
        code = request.POST.get('otp_code')
        if totp.verify(code):
            request.session['otp_verified'] = True
            return redirect('vaultcore:reset_password_form')

        messages.error(request, 'Invalid OTP.')
    if not profile.is_2fa_enabled:
        return redirect('vaultcore:enter_secondary')
    
    return render(request, 'vaultcore/verify_existing_otp.html')


#@login_required
def setup_2fa_reset(request):
    user_id = request.session.get('reset_user_id')
    if not user_id:
        return redirect('vaultcore:custom_reset')

    user = User.objects.get(id=user_id)
    profile, _ = UserProfile.objects.get_or_create(user=user)

    if not profile.otp_secret:
        profile.otp_secret = pyotp.random_base32()
        profile.save()

    totp = pyotp.TOTP(profile.otp_secret)
    uri = totp.provisioning_uri(user.username, issuer_name="SecureVault")
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_img = base64.b64encode(buf.getvalue()).decode()

    if request.method == 'POST':
        code = request.POST.get("otp_code")
        if totp.verify(code):
            profile.is_2fa_enabled = True
            profile.save()
            request.session['otp_verified'] = True
            return redirect('vaultcore:reset_password_form')
        return render(request, 'vaultcore/setup_2fa_reset.html', {'qr': qr_img, 'error': 'Invalid OTP.'})

    return render(request, 'vaultcore/setup_2fa_reset.html', {'qr': qr_img})


def custom_password_reset(request):
    user_id = request.session.get('reset_user_id')
    verified = request.session.get('otp_verified')

    if not user_id or not verified:
        return redirect('vaultcore:start_reset_password')

    user = User.objects.get(id=user_id)

    if request.method == 'POST':
        new_pass = request.POST.get('new_password1')
        confirm_pass = request.POST.get('new_password2')

        if not new_pass or not confirm_pass:
            return render(request, 'vaultcore/custom_password_reset.html', {
                'error': 'Password fields cannot be empty.'
            })

        if new_pass != confirm_pass:
            return render(request, 'vaultcore/custom_password_reset.html', {
                'error': 'Passwords do not match.'
            })

        user.set_password(new_pass)
        print(f"🔐 Stored password hash: {user.password}")
        user.save()

        from axes.utils import reset
        reset(username=user.username, ip=request.META.get('REMOTE_ADDR'))

        request.session.flush()
        messages.success(request, 'Password successfully updated.')
        return redirect('login')  # ✅ Correct redirect

    # ✅ This was likely never hit due to early exit
    return render(request, 'vaultcore/custom_password_reset.html')

def enter_secondary_identifier(request):
    identifier = request.session.get('identifier')
    if not identifier:
        return redirect('vaultcore:custom_reset')

    if request.method == 'POST':
        secondary = request.POST.get('secondary')
        user = None

        # Step 1: Determine original type
        if '@' in identifier:
            # Original was email, now match username + email
            user = User.objects.filter(email=identifier, username=secondary).first()
        else:
            # Original was username, now match email + username
            user = User.objects.filter(username=identifier, email=secondary).first()

        if user:
            request.session['reset_user_id'] = user.id
            request.session['otp_verified'] = False
            return redirect('vaultcore:setup_2fa_reset')
        else:
            messages.error(request, 'No user found with matching credentials.')
            return render(request, 'vaultcore/enter_secondary.html')

    return render(request, 'vaultcore/enter_secondary.html')
