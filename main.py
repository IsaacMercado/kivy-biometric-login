from typing import Any, Callable, NoReturn

from jnius import JavaClass, PythonJavaClass, autoclass, cast, java_method
from kivy import platform
from kivy.app import App
from kivy.properties import BooleanProperty
from kivy.uix.button import Button
from kivy.uix.widget import Widget


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


class BiometricAuthentication(object):
    class AuthenticationCallback(PythonJavaClass):
        __javainterfaces__ = [
            'org/example/biometric_login/HelperBiometric'
            '$BiometricCallback'
        ]
        __javacontext__ = 'app'

        def __init__(self, callback: Callable[[str, Any, Any], NoReturn], *args, **kwargs):
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

    class OnClickListener(PythonJavaClass):
        __javainterfaces__ = [
            'android/content/DialogInterface'
            '$OnClickListener'
        ]
        __javacontext__ = 'app'

        def __init__(self, callback: Callable[[JavaClass, int], NoReturn], *args, **kwargs):
            self.callback = callback
            PythonJavaClass.__init__(self, *args, **kwargs)

        @java_method('(Landroid/content/DialogInterface;I)V')
        def onClick(self, dialog: JavaClass, which: int):
            if self.callback:
                self.callback(dialog, which)

    class OnCancelListener(PythonJavaClass):
        __javainterfaces__ = [
            'android/os/CancellationSignal'
            '$OnCancelListener'
        ]
        __javacontext__ = 'app'

        def __init__(self, callback: Callable[[], NoReturn], *args, **kwargs):
            self.callback = callback
            PythonJavaClass.__init__(self, *args, **kwargs)

        @java_method('()V')
        def onCancel(self):
            if self.callback:
                self.callback()

    def __init__(
        self,
        title: str,
        subtitle: str,
        description: str,
        allowed_authenticators: int,
        confirmation_required: bool,
        negative_button_text: str,
        on_authentication_succeeded: Callable[[JavaClass], NoReturn] | None = None,
        on_authentication_error: Callable[[int, str], NoReturn] | None = None,
        on_authentication_failed: Callable[[], NoReturn] | None = None,
    ):
        super().__init__()
        self.allowed_authenticators = allowed_authenticators

        PythonActivity = autoclass(
            'org.kivy.android.PythonActivity'
        )
        PromptBuilder = autoclass(
            'android.hardware.biometrics'
            '.BiometricPrompt'
            '$Builder'
        )
        BiometricCallbackImpl = autoclass(
            'org.example.biometric_login'
            '.HelperBiometric'
            '$BiometricCallbackImpl'
        )
        Executors = autoclass('java.util.concurrent.Executors')

        context = PythonActivity.mActivity.getApplicationContext()
        prompt_builder = PromptBuilder(context)

        if title:
            prompt_builder = prompt_builder.setTitle(title)

        if subtitle:
            prompt_builder = prompt_builder.setSubtitle(subtitle)

        if description:
            prompt_builder = prompt_builder.setDescription(description)

        if allowed_authenticators:
            prompt_builder = prompt_builder.setAllowedAuthenticators(
                allowed_authenticators
            )

        if confirmation_required:
            prompt_builder = prompt_builder.setConfirmationRequired(
                confirmation_required
            )

        if negative_button_text:
            executor = Executors.newSingleThreadExecutor()
            prompt_builder = prompt_builder.setNegativeButton(
                negative_button_text,
                executor,
                BiometricAuthentication.OnClickListener(
                    lambda dialog, which: print(dialog, which)
                )
            )

        self.prompt = prompt_builder.build()

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
        Executors = autoclass('java.util.concurrent.Executors')
        CancellationSignal = autoclass('android.os.CancellationSignal')
        executor = Executors.newSingleThreadExecutor()
        self.prompt.authenticate(
            CancellationSignal(),
            executor,
            self.authentication_callback,
        )

    def can_authenticate(self):
        BiometricManager = autoclass(
            'android.hardware.biometrics.BiometricManager'
        )
        PythonActivity = autoclass(
            'org.kivy.android.PythonActivity'
        )

        context = PythonActivity.mActivity.getApplicationContext()
        biometric_manager = context.getSystemService(BiometricManager._class)

        return biometric_manager.canAuthenticate(
            self.allowed_authenticators
        )


class BiometricLoginApp(App):
    is_authenticated = BooleanProperty(False)

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
            title='Sample App Authentication',
            subtitle='Please login to get access',
            description='Sample App is using Android biometric authentication',
            allowed_authenticators=Authenticators.BIOMETRIC_STRONG,
            confirmation_required=True,
            negative_button_text='Cancel',
            on_authentication_succeeded=lambda result: setattr(
                self, 'is_authenticated', True
            ),
        )

        if biometric_authentication.can_authenticate() == 0:
            biometric_authentication.authenticate()


if __name__ == '__main__':
    BiometricLoginApp().run()
