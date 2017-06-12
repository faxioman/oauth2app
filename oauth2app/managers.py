from django.db import models
import jwt
from django.conf import settings


class AccessTokenManager(models.Manager):
    def create(self, scope, *args, **kwargs):
        obj = self.model(*args, **kwargs)
        if hasattr(settings, 'OAUTH2_USE_JWT_TOKEN') and settings.OAUTH2_USE_JWT_TOKEN:
            payload = {
                "iss": settings.OAUTH2_JWT_ISSUER,
                "sub": str(obj.user.pk),
                "aud": settings.OAUTH2_JWT_AUDIENCE,
                "iat": obj.issue,
                "exp": obj.expire,
                "scope": " ".join(x.key if hasattr(x, 'key') else x['key'] for x in scope) # scope may be a dict or an AccessRange
            }

            # claims <-> user fields mapping
            for (claim, field) in settings.OAUTH2_JWT_CLAIMS_USER_MAPPING.iteritems():
                payload[claim] = getattr(obj.user, field)

            obj.token = jwt.encode(payload, settings.OAUTH2_JWT_KEY, algorithm='HS256')

        obj.save()
        obj.scope = scope
        obj.save()
        return obj
