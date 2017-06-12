from django.db import models


class AccessTokenManager(models.Manager):
    def create(self, scope, *args, **kwargs):
        obj = super(AccessTokenManager, self).create(*args, **kwargs)
        obj.scope = scope
        obj.generate_token()
        obj.save()
        return obj
