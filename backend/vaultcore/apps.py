from django.apps import AppConfig


class VaultcoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vaultcore'

    def ready(self):
        import vaultcore.signals