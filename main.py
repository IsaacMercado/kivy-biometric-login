from urllib.parse import urljoin

import httpx
from kivy import platform
from kivy.app import App
from kivy.properties import BooleanProperty, DictProperty, ObjectProperty
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen
from kivy.uix.widget import Widget

client = httpx.Client(base_url='http://localhost:8000')


def hide_widget(widget: Widget, dohide=True):
    if hasattr(widget, 'saved_attrs'):
        if not dohide:
            (
                widget.height,
                widget.size_hint_y,
                widget.opacity,
                widget.disabled,
            ) = widget.saved_attrs
            del widget.saved_attrs
    elif dohide:
        widget.saved_attrs = (
            widget.height,
            widget.size_hint_y,
            widget.opacity,
            widget.disabled,
        )
        (
            widget.height,
            widget.size_hint_y,
            widget.opacity,
            widget.disabled,
        ) = 0, None, 0, True


class LoginScreen(Screen):
    biometric_label: Label | None = ObjectProperty()
    biometric_prompt = ObjectProperty()
    biometric_crypto_manager = ObjectProperty()
    biometric_key_name: str = 'biometric_login'
    data_form: dict = DictProperty({
        'username': None,
        'password': None,
    })
    allows_biometric_auth: bool = BooleanProperty(False)

    def __init__(self, **kw):
        super().__init__(**kw)
        self.bind(
            biometric_label=self.check_allows_biometric_auth,
            allows_biometric_auth=self.check_allows_biometric_auth,
        )

    def on_biometric_label(self, *args):
        if self.biometric_label:
            self.biometric_label.bind(
                on_ref_press=lambda label, value: value == 'biometrics' and self.authenticate()
            )

    def go_main(self):
        self.manager.current = 'main'

    def check_allows_biometric_auth(self, *args):
        if self.biometric_label:
            hide_widget(self.biometric_label, not self.allows_biometric_auth)

    def on_pre_enter(self, *args):
        if platform == 'android':
            from android.permissions import (Permission, check_permission,
                                             request_permissions)

            from biometrics import (BiometricManager, BiometricPrompt,
                                    CryptographyManager)

            if not check_permission(Permission.USE_BIOMETRIC):
                request_permissions([Permission.USE_BIOMETRIC])

            if BiometricManager().can_authenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            ) == BiometricManager.BIOMETRIC_SUCCESS:
                self.allows_biometric_auth = True
                self.biometric_prompt = BiometricPrompt(
                    title='Sample App Authentication',
                    subtitle='Please login to get access',
                    description='Sample App is using Android biometric authentication',
                    allowed_authenticators=BiometricManager.Authenticators.BIOMETRIC_STRONG,
                    confirmation_required=True,
                    negative_button_text='Cancel',
                    on_authentication_succeeded=self.on_authentication_succeeded,
                )
                self.biometric_crypto_manager = CryptographyManager(
                    self.biometric_key_name,
                )

    def on_authentication_succeeded(self, result):
        signature = result.getCryptoObject().getSignature()
        username = self.data_form['username']

        httpx.Client
        httpx.AsyncClient

        response = client.post(
            "/users/challenge",
            data={'username': username},
        )
        challenge: str = response.json()['challenge']

        signature.update(challenge.encode())
        sign = signature.sign()

        response = client.post(
            "/users/verify/challenge",
            data={
                'username': username,
                'signature': bytes(sign).decode(),
            },
        )

        if response.status_code == 200:
            self.go_main()

    def authenticate(self):
        if platform == 'android' and self.biometric_prompt:
            self.biometric_prompt.authenticate(
                self.biometric_crypto_manager,
            )

    def login(self):
        print(self.data_form)
        self.go_main()


class MainScreen(Screen):
    def logout(self):
        self.manager.current = 'login'


class BiometricLoginApp(App):
    pass


if __name__ == '__main__':
    BiometricLoginApp().run()
