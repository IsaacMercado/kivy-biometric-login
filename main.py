from typing import Callable

from jnius import JavaClass, PythonJavaClass, autoclass, java_method, cast
from kivy import platform
from kivy.app import App
from kivy.properties import BooleanProperty
from kivy.uix.button import Button


class BiometricAuthentication(object):
    class AuthenticationCallback(PythonJavaClass):
        __javainterfaces__ = [
            'org/example/biometric_login/HelperBiometric'
            '$BiometricCallback'
        ]
        __javacontext__ = 'app'

        def __init__(self, callback, *args, **kwargs):
            self.callback = callback
            PythonJavaClass.__init__(self, *args, **kwargs)

        @java_method('(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)V')
        def onBiometricAuthenticationSucceeded(self, result):
            if self.callback:
                self.callback('success', result)

        @java_method('(ILjava/lang/CharSequence;)V')
        def onBiometricAuthenticationError(self, errorCode: int, errString: str):
            if self.callback:
                self.callback('error', errorCode, errString)

        @java_method('()V')
        def onBiometricAuthenticationFailed(self):
            if self.callback:
                self.callback('failed')

    def __init__(
        self,
        title: str = None,
        subtitle: str = None,
        description: str = None,
        allowed_authenticators: int = None,
        confirmation_required: bool = None,
        negative_button_text: str = None,
        on_authentication_succeeded: Callable[[JavaClass], None] = None,
        on_authentication_error: Callable[[int, str], None] = None,
        on_authentication_failed: Callable[[], None] = None,
    ):
        super().__init__()
        self.allowed_authenticators = allowed_authenticators

        PromptInfoBuilder = autoclass(
            'androidx.biometric'
            '.BiometricPrompt'
            '$PromptInfo$Builder'
        )
        BiometricCallbackImpl = autoclass(
            'org.example.biometric_login'
            '.HelperBiometric$BiometricCallbackImpl'
        )

        prompt_info_builder = PromptInfoBuilder()

        if title:
            prompt_info_builder.setTitle(title)

        if subtitle:
            prompt_info_builder.setSubtitle(subtitle)

        if description:
            prompt_info_builder.setDescription(description)

        if allowed_authenticators:
            prompt_info_builder.setAllowedAuthenticators(
                allowed_authenticators
            )

        if confirmation_required:
            prompt_info_builder.setConfirmationRequired(
                confirmation_required
            )

        if negative_button_text:
            prompt_info_builder.setNegativeButtonText(
                negative_button_text
            )

        self.prompt_info = prompt_info_builder.build()

        def __callback(status, *args):
            if status == 'success':
                on_authentication_succeeded(*args)
            elif status == 'error':
                on_authentication_error(*args)
            elif status == 'failed':
                on_authentication_failed()

        self.authentication_callback = BiometricCallbackImpl(
            BiometricAuthentication.AuthenticationCallback(
                __callback,
            )
        )

    def authenticate(self):
        mActivity = autoclass("org.kivy.android.PythonActivity").mActivity
        ContextCompat = autoclass('androidx.core.content.ContextCompat')
        BiometricPrompt = autoclass('androidx.biometric.BiometricPrompt')
        executor = ContextCompat.getMainExecutor(mActivity)

        biometric_prompt = BiometricPrompt(
            cast('androidx.appcompat.app.AppCompatActivity', mActivity),
            executor,
            self.authentication_callback,
        )
        biometric_prompt.authenticate(self.prompt_info)

    def can_authenticate(self):
        BiometricManager = autoclass('androidx.biometric.BiometricManager')
        mActivity = autoclass("org.kivy.android.PythonActivity").mActivity
        biometric_manager = getattr(BiometricManager, 'from')(mActivity)
        return biometric_manager.canAuthenticate(
            # self.allowed_authenticators
        )


class BiometricLoginApp(App):
    is_authenticated = BooleanProperty(False)

    def build(self):
        button = Button(text='Authenticate')
        button.bind(on_press=self.autenticate)
        return button

    def on_is_authenticated(self, instance, value):
        if value:
            print('Authenticated')

    def autenticate(self, instance: Button):
        Authenticators = autoclass(
            'android.hardware.biometrics'
            '.BiometricManager'
            '$Authenticators'
        )
        biometric_authentication = BiometricAuthentication(
            title='Biometric Authentication',
            subtitle='Subtitle',
            description='Description',
            # allowed_authenticators=Authenticators.BIOMETRIC_STRONG,
            confirmation_required=True,
            negative_button_text='Cancel',
            on_authentication_succeeded=lambda result: setattr(
                self, 'is_authenticated', True
            ),
        )
        if biometric_authentication.can_authenticate():
            biometric_authentication.authenticate()


if __name__ == '__main__':
    BiometricLoginApp().run()
