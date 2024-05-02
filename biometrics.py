import base64
from enum import IntFlag
from typing import Any, Callable, NoReturn

from jnius import JavaClass, PythonJavaClass, autoclass, cast, java_method

BiometricCallbackImpl = autoclass(
    'org.example.biometric_login'
    '.HelperBiometric'
    '$BiometricCallbackImpl'
)
_BiometricManager = autoclass(
    'android.hardware.biometrics'
    '.BiometricManager'
)
_BiometricManager.Authenticators = autoclass(
    'android.hardware.biometrics'
    '.BiometricManager'
    '$Authenticators'
)
CancellationSignal = autoclass(
    'android.os'
    '.CancellationSignal'
)
Executors = autoclass(
    'java.util.concurrent'
    '.Executors'
)
PromptBuilder = autoclass(
    'android.hardware.biometrics'
    '.BiometricPrompt'
    '$Builder'
)
PythonActivity = autoclass(
    'org.kivy.android.PythonActivity'
)


class BiometricManager:
    class Authenticators(IntFlag):
        BIOMETRIC_STRONG = _BiometricManager.Authenticators.BIOMETRIC_STRONG
        BIOMETRIC_WEAK = _BiometricManager.Authenticators.BIOMETRIC_WEAK
        DEVICE_CREDENTIAL = _BiometricManager.Authenticators.DEVICE_CREDENTIAL

    BIOMETRIC_ERROR_HW_UNAVAILABLE = _BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
    BIOMETRIC_ERROR_NONE_ENROLLED = _BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
    BIOMETRIC_ERROR_NO_HARDWARE = _BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE
    BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED = _BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED
    BIOMETRIC_SUCCESS = _BiometricManager.BIOMETRIC_SUCCESS

    def __init__(self) -> None:
        context = PythonActivity.mActivity.getApplicationContext()
        self.__manager = context.getSystemService(_BiometricManager._class)

    def can_authenticate(self, authenticators: int) -> int:
        return self.__manager.canAuthenticate(authenticators)


class BiometricPrompt(object):
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
        on_succeeded: Callable[[JavaClass], NoReturn] | None = None,
        on_error: Callable[[int, str], NoReturn] | None = None,
        on_failed: Callable[[], NoReturn] | None = None,
        on_cancel: Callable[[], NoReturn] | None = None,
        on_click_negative_button: Callable[[JavaClass, int], NoReturn] | None = None,  # noqa
    ):
        super().__init__()
        self.__auth_callbacks = {
            'success': on_succeeded,
            'error': on_error,
            'failed': on_failed,
        }
        self.__on_cancel = on_cancel
        self.__cancel_signal = None

        context = PythonActivity.mActivity.getApplicationContext()
        prompt_builder = PromptBuilder(context)

        prompt_builder.setTitle(
            title
        ).setSubtitle(
            subtitle
        ).setDescription(
            description
        ).setAllowedAuthenticators(
            allowed_authenticators,
        ).setConfirmationRequired(
            confirmation_required,
        )

        executor = Executors.newSingleThreadExecutor()
        prompt_builder.setNegativeButton(
            negative_button_text,
            executor,
            BiometricPrompt.OnClickListener(
                on_click_negative_button,
            ),
        )

        self.__prompt = prompt_builder.build()
        self.__auth_callback = BiometricCallbackImpl(
            BiometricPrompt.AuthenticationCallback(
                lambda status, *args: self.__auth_callbacks[status](*args),
            )
        )

    def cancel_authentication(self):
        if self.__cancel_signal and not self.__cancel_signal.isCanceled():
            self.__cancel_signal.cancel()

    def authenticate(self, crypto_object: JavaClass | None = None):
        executor = Executors.newSingleThreadExecutor()
        self.__cancel_signal = CancellationSignal()

        if self.__on_cancel:
            self.__cancel_signal.setOnCancelListener(
                BiometricPrompt.OnCancelListener(self.__on_cancel)
            )

        if crypto_object:
            self.__prompt.authenticate(
                crypto_object,
                self.__cancel_signal,
                executor,
                self.__auth_callback,
            )
        else:
            self.__prompt.authenticate(
                self.__cancel_signal,
                executor,
                self.__auth_callback,
            )

        self.__cancel_signal = None


KeyGenParameterSpec = autoclass(
    'android.security.keystore'
    '.KeyGenParameterSpec'
)
KeyProperties = autoclass(
    'android.security.keystore'
    '.KeyProperties'
)
KeyStore = autoclass(
    'java.security'
    '.KeyStore'
)
KeyPairGenerator = autoclass(
    'java.security'
    '.KeyPairGenerator'
)
KeyGenParameterSpecBuilder = autoclass(
    'security.keystore'
    '.KeyGenParameterSpec'
    '$Builder'
)
ECGenParameterSpec = autoclass(
    'java.security.spec'
    '.ECGenParameterSpec'
)
Signature = autoclass(
    'java.security'
    '.Signature'
)
CryptoObject = autoclass(
    'androidx.biometric'
    '.BiometricPrompt'
    '$CryptoObject'
)


class CryptographyManager(object):
    key_store = "AndroidKeyStore"
    algorithm = "SHA256withECDSA"
    digest = KeyProperties.DIGEST_SHA256
    spec = ECGenParameterSpec("secp256r1")

    def __init__(self, key_name: str) -> None:
        super().__init__()
        self.__key_name = key_name

        if self.get_private_key() is None:
            self.generate_secret_key()

    def generate_secret_key(self):
        keygen_builder = KeyGenParameterSpecBuilder(
            self.__key_name,
            KeyProperties.PURPOSE_SIGN,
        )
        keygen_builder.setDigests(self.digest)
        keygen_builder.setAlgorithmParameterSpec(self.spec)
        keygen_builder.setUserAuthenticationRequired(True)
        # keygen_builder.setInvalidatedByBiometricEnrollment(True)
        keygen_spec = keygen_builder.build()

        key_generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            self.android_key_store
        )

        key_generator.init(keygen_spec)
        return key_generator.generateKeyPair()

    def get_private_key(self):
        key_store = KeyStore.getInstance(self.android_key_store)

        # Before the keystore can be accessed, it must be loaded.
        key_store.load(None)
        return key_store.getKey(self.__key_name, None)

    def get_certificate(self):
        key_store = KeyStore.getInstance(self.android_key_store)

        # Before the keystore can be accessed, it must be loaded.
        key_store.load(None)
        return key_store.getCertificate(self.__key_name)

    def get_public_key(self):
        return self.get_certificate().getPublicKey()

    def get_PEM_public_key(self):
        encoded = self.get_public_key().getEncoded()
        return (
            '-----BEGIN PUBLIC KEY-----\n'
            f'{base64.b64encode(bytes(encoded)).decode('ascii')}\n'
            '-----END PUBLIC KEY-----'
        )

    def get_signature(self):
        signature = Signature.getInstance(self.algorithm)
        key = self.get_private_key()
        signature.initSign(key)
        return signature

    def get_crypto_object(self):
        return CryptoObject(self.get_signature())
