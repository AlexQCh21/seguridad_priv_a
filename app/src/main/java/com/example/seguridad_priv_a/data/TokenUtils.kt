package com.example.seguridad_priv_a.data

import java.security.SecureRandom
import java.util.*

object TokenUtils {
    fun generateTemporaryToken(userId: String): String {
        // Genera un token aleatorio basado en usuario y tiempo actual
        val random = ByteArray(24)
        SecureRandom().nextBytes(random)
        val base = "$userId-${System.currentTimeMillis()}-${Base64.getEncoder().encodeToString(random)}"
        return Base64.getEncoder().encodeToString(base.toByteArray())
    }
}