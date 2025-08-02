package com.example.seguridad_priv_a.data

import android.util.Base64

object AntiTamperingUtils {
    fun isDebugging(): Boolean = android.os.Debug.isDebuggerConnected()

    fun isRunningOnEmulator(): Boolean {
        val fingerprint = android.os.Build.FINGERPRINT
        return (fingerprint.startsWith("generic") || fingerprint.contains("vbox") || fingerprint.contains("test-keys"))
    }
}

object CryptoConstants {
    val ENCRYPTED_SECRET = "Z3VhcmRhZG9fZW4tY3J5cHRhZG8=" // Base64
    fun getDecryptedSecret(): String = String(android.util.Base64.decode(ENCRYPTED_SECRET, Base64.DEFAULT))
}

