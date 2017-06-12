#-*- coding: utf-8 -*-

try: import simplejson as json
except ImportError: import json
from base64 import b64encode
from django.utils import unittest
from django.contrib.auth.models import User
from oauth2app.models import Client
from django.test.client import Client as DjangoTestClient
import jwt
from django.conf import settings


USER_USERNAME = "testuser"
USER_PASSWORD = "testpassword"
USER_EMAIL = "user@example.com"
USER_FIRSTNAME = "Foo"
USER_LASTNAME = "Bar"
CLIENT_USERNAME = "client"
CLIENT_EMAIL = "client@example.com"
REDIRECT_URI = "http://example.com/callback"


class GrantTypeTestCase(unittest.TestCase):

    user = None
    client_holder = None
    client_application = None

    def setUp(self):
        self.user = User.objects.create_user(
            USER_USERNAME,
            USER_EMAIL,
            USER_PASSWORD)
        self.user.first_name = USER_FIRSTNAME
        self.user.last_name = USER_LASTNAME
        self.user.save()
        self.client = User.objects.create_user(CLIENT_USERNAME, CLIENT_EMAIL)
        self.client_application = Client.objects.create(
            name="TestApplication",
            user=self.client)

    def tearDown(self):
        self.user.delete()
        self.client.delete()
        self.client_application.delete()

    def test_00_grant_type_client_credentials(self):
        user = DjangoTestClient()
        user.login(username=USER_USERNAME, password=USER_PASSWORD)
        client = DjangoTestClient()
        parameters = {
            "client_id": self.client_application.key,
            "grant_type": "client_credentials",
            "redirect_uri": REDIRECT_URI}
        basic_auth = b64encode("%s:%s" % (self.client_application.key,
            self.client_application.secret))
        response = client.get(
            "/oauth2/token",
            parameters,
            HTTP_AUTHORIZATION="Basic %s" % basic_auth)
        token = json.loads(response.content)

    def test_01_grant_type_refresh_token(self):
        user = DjangoTestClient()
        user.login(username=USER_USERNAME, password=USER_PASSWORD)
        client = DjangoTestClient()
        parameters = {
            "client_id": self.client_application.key,
            "grant_type": "client_credentials",
            "redirect_uri": REDIRECT_URI}
        basic_auth = b64encode("%s:%s" % (self.client_application.key,
                                          self.client_application.secret))
        response = client.get(
            "/oauth2/token",
            parameters,
            HTTP_AUTHORIZATION="Basic %s" % basic_auth)
        token = json.loads(response.content)

        parameters = {
            "client_id": self.client_application.key,
            "grant_type": "refresh_token",
            "refresh_token": token['refresh_token']}
        basic_auth = b64encode("%s:%s" % (self.client_application.key,
                                          self.client_application.secret))
        response = client.post(
            "/oauth2/token",
            parameters,
            HTTP_AUTHORIZATION="Basic %s" % basic_auth)
        token = json.loads(response.content)
        self.assertIsNotNone(token['access_token'])

    def test_02_grant_type_refresh_token_jwt(self):
        user = DjangoTestClient()
        user.login(username=USER_USERNAME, password=USER_PASSWORD)
        client = DjangoTestClient()
        parameters = {
            "client_id": self.client_application.key,
            "grant_type": "client_credentials",
            "redirect_uri": REDIRECT_URI}
        basic_auth = b64encode("%s:%s" % (self.client_application.key,
                                          self.client_application.secret))
        response = client.get(
            "/oauth2/token",
            parameters,
            HTTP_AUTHORIZATION="Basic %s" % basic_auth)
        token = json.loads(response.content)

        parameters = {
            "client_id": self.client_application.key,
            "grant_type": "refresh_token",
            "refresh_token": token['refresh_token']}
        basic_auth = b64encode("%s:%s" % (self.client_application.key,
                                          self.client_application.secret))
        response = client.post(
            "/oauth2/token",
            parameters,
            HTTP_AUTHORIZATION="Basic %s" % basic_auth)
        token = json.loads(response.content)

        jwt_payload = jwt.decode(token['access_token'], settings.OAUTH2_JWT_KEY, algorithms=['HS256'], audience=settings.OAUTH2_JWT_AUDIENCE)
        self.assertEqual(jwt_payload['sub'], str(self.client_application.user.pk))
