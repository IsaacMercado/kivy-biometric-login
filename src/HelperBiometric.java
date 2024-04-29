package org.example.biometric_login;

import android.hardware.biometrics.BiometricPrompt;

public class HelperBiometric {
    public static interface BiometricCallback {
        void onBiometricAuthenticationError(int errorCode, CharSequence errString);

        void onBiometricAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result);

        void onBiometricAuthenticationFailed();
    }

    public static class BiometricCallbackImpl extends BiometricPrompt.AuthenticationCallback {
        private BiometricCallback biometricCallback;

        public BiometricCallbackImpl(BiometricCallback biometricCallback) {
            this.biometricCallback = biometricCallback;
        }

        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            biometricCallback.onBiometricAuthenticationError(errorCode, errString);
        }

        @Override
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            biometricCallback.onBiometricAuthenticationSucceeded(result);
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            biometricCallback.onBiometricAuthenticationFailed();
        }
    }
}
