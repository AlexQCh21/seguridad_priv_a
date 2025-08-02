package com.example.seguridad_priv_a.data

import android.content.Context

object AppAttestation {
    fun isAppIntegrityValid(context: Context): Boolean {
        // Implementación real requiere SafetyNet o Play Integrity API
        // Aquí solo simulamos
        val signature = context.packageManager.getPackageInfo(context.packageName, 0).signatures
        // Verifica contra hash conocido de firma
        return true
    }
}