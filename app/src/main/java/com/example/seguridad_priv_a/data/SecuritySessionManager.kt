package com.example.seguridad_priv_a.data

import android.content.Context

object SecuritySessionManager {
    private var activeSession: SecuritySession? = null

    fun startSession(userId: String): SecuritySession {
        val token = TokenUtils.generateTemporaryToken(userId)
        activeSession = SecuritySession(userId, token, System.currentTimeMillis())
        return activeSession!!
    }

    fun getActiveSession(context: Context): SecuritySession? = activeSession
}

data class SecuritySession(val userId: String, val token: String, val startTime: Long) {
    fun isTokenValid(): Boolean = System.currentTimeMillis() - startTime < (15 * 60 * 1000) // 15 min
    fun hasRole(role: String): Boolean {
        // Simula RBAC
        return true // Implementa lógica real
    }
}