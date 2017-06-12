#-*- coding: utf-8 -*-

try: import simplejson as json
except ImportError: import json
from .base import *
import jwt
from django.conf import settings


class BearerTestCase(BaseTestCase):

    def test_00_bearer(self):
        client = DjangoTestClient()
        token = self.get_token()
        response = client.get(
            "/api/email_str",
            {},
            HTTP_AUTHORIZATION="Bearer %s" % token)
        self.assertEqual(response.status_code, 200)
        response = client.get(
            "/api/email_str",
            {},
            HTTP_AUTHORIZATION="Bearer2 %s" % token)
        self.assertEqual(response.status_code, 401)
        response = client.get(
            "/api/email_str",
            {},
            HTTP_AUTHORIZATION="Bearer !!!%s" % token)
        self.assertEqual(response.status_code, 401)

    def test_01_json_bearer(self):
        client = DjangoTestClient()
        token = self.get_token()
        response = client.get(
            "/api/email_json",
            {},
            HTTP_AUTHORIZATION="Bearer %s" % token)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("email" in json.loads(response.content))
        response = client.get(
            "/api/email_json",
            {},
            HTTP_AUTHORIZATION="Bearer2 %s" % token)
        self.assertEqual(response.status_code, 401)
        self.assertTrue("error" in json.loads(response.content))
        response = client.get(
            "/api/email_json",
            {},
            HTTP_AUTHORIZATION="Bearer !!!%s" % token)
        self.assertEqual(response.status_code, 401)
        self.assertTrue("error" in json.loads(response.content))

    def test_02_automatic_fail(self):
        client = DjangoTestClient()
        token = self.get_token()
        response = client.get(
            "/api/automatic_error_str",
            {},
            HTTP_AUTHORIZATION="Bearer %s" % token)
        self.assertEqual(response.status_code, 401)
        response = client.get(
            "/api/automatic_error_json",
            {},
            HTTP_AUTHORIZATION="Bearer %s" % token)
        self.assertEqual(response.status_code, 401)

    def test_03_jwt(self):
        token = self.get_token()
        jwt_payload = jwt.decode(token, settings.OAUTH2_JWT_KEY, algorithms=['HS256'], audience=settings.OAUTH2_JWT_AUDIENCE)
        self.assertEqual(jwt_payload['sub'], str(self.user.pk))

    def test_04_jwt_claims_mapping(self):
        token = self.get_token()
        jwt_payload = jwt.decode(token, settings.OAUTH2_JWT_KEY, algorithms=['HS256'], audience=settings.OAUTH2_JWT_AUDIENCE)
        self.assertEqual(jwt_payload['given_name'], self.user.first_name)
        self.assertEqual(jwt_payload['email'], self.user.email)
        self.assertEqual(jwt_payload['family_name'], self.user.last_name)

