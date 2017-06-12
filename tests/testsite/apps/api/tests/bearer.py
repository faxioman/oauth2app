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

    def test_05_jwt_scope_claim(self):
        user = DjangoTestClient()
        user.login(username=USER_USERNAME, password=USER_PASSWORD)
        parameters = {
            "client_id": self.client_application.key,
            "scope": "first_name last_name",
            "redirect_uri": REDIRECT_URI,
            "response_type": "code"}
        response = user.get("/oauth2/authorize_first_and_last_name?%s" % urlencode(parameters))
        qs = parse_qs(urlparse(response['location']).query)
        code = qs['code']
        client = DjangoTestClient()
        parameters = {
            "client_id": self.client_application.key,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "scope": "first_name last_name"}
        basic_auth = b64encode("%s:%s" % (self.client_application.key, self.client_application.secret))
        response = client.get(
            "/oauth2/token",
            parameters,
            HTTP_AUTHORIZATION="Basic %s" % basic_auth)

        token = json.loads(response.content)["access_token"]
        jwt_payload = jwt.decode(token, settings.OAUTH2_JWT_KEY, algorithms=['HS256'], audience=settings.OAUTH2_JWT_AUDIENCE)

        self.assertEqual(jwt_payload['family_name'], self.user.last_name)
        self.assertEqual(jwt_payload['given_name'], self.user.first_name)
