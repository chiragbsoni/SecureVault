from django.contrib import admin
from django.urls import path, include
from vaultcore.views import CustomLoginView, register_view
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('vaultcore.urls')),
    path('account/login/', CustomLoginView.as_view(), name='login'),
    path('account/register/', register_view, name='register'),
    path('account/', include('django.contrib.auth.urls')),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('reset_password/', auth_views.PasswordResetView.as_view(), name='password_reset'),

]