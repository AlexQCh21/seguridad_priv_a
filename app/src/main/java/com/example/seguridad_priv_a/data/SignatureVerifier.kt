package com.example.seguridad_priv_a.data

import android.content.Context

object SignatureVerifier {
    fun isSignatureValid(context: Context): Boolean {
        val expected = "SHA256_HASH_FIRMA_REAL"
        val signatures = context.packageManager.getPackageInfo(context.packageName, 0).signatures
        // Calcula hash de la firma y compara
        return true // Implementa lógica real
    }
}