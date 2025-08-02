package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.security.PrivateKey
import java.security.Signature
import android.util.Base64

class SecurityAuditManager(private val context: Context) {

    private val auditPrefs: SharedPreferences by lazy {
        context.getSharedPreferences("audit_logs", Context.MODE_PRIVATE)
    }

    private val RATE_LIMIT_WINDOW_MS = 60_000L // 1 minuto
    private val MAX_SENSITIVE_OPS = 3 // máx. 3 ops sensibles/minuto

    private val sensitiveOps = listOf("DATA_STORAGE", "DATA_ACCESS", "KEY_MANAGEMENT")

    // Para demo: cuenta intentos recientes por categoría
    fun isRateLimited(category: String): Boolean {
        if (category !in sensitiveOps) return false
        val now = SystemClock.elapsedRealtime()
        val opsKey = "rate_$category"
        val listRaw = auditPrefs.getString(opsKey, "") ?: ""
        val ops = if (listRaw.isBlank()) mutableListOf<Long>() else listRaw.split(",").map { it.toLong() }.toMutableList()
        val filtered = ops.filter { now - it < RATE_LIMIT_WINDOW_MS }
        return filtered.size >= MAX_SENSITIVE_OPS
    }

    fun recordSensitiveOp(category: String) {
        val now = SystemClock.elapsedRealtime()
        val opsKey = "rate_$category"
        val listRaw = auditPrefs.getString(opsKey, "") ?: ""
        val ops = if (listRaw.isBlank()) mutableListOf<Long>() else listRaw.split(",").map { it.toLong() }.toMutableList()
        val filtered = ops.filter { now - it < RATE_LIMIT_WINDOW_MS }.toMutableList()
        filtered.add(now)
        auditPrefs.edit().putString(opsKey, filtered.joinToString(",")).apply()
    }

    // Detecta patrones anómalos: muchos intentos fallidos en corto
    fun detectSuspiciousAccess(): Boolean {
        val now = System.currentTimeMillis()
        val logsStr = auditPrefs.getString("logs", "") ?: ""
        val logs = if (logsStr.isBlank()) listOf() else logsStr.split("\n")
        val lastMinute = logs.filter { it.contains("FAILED") && now - extractTimestamp(it) < 60_000 }
        return lastMinute.size >= 5
    }

    private fun extractTimestamp(log: String): Long {
        return try {
            val parts = log.split(" - ")[0]
            val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
            sdf.parse(parts)?.time ?: 0L
        } catch (e: Exception) { 0L }
    }

    // Alerta si se detecta patrón anómalo
    fun generateAlertIfNeeded(): Boolean {
        if (detectSuspiciousAccess()) {
            // Aquí se podría notificar al usuario/administrador
            logAudit("ALERT", "Patrón anómalo detectado: múltiples accesos fallidos")
            return true
        }
        return false
    }

    // Guarda logs tipo JSON
    fun logAudit(category: String, action: String) {
        val timestamp = System.currentTimeMillis()
        val obj = JSONObject()
        obj.put("timestamp", timestamp)
        obj.put("category", category)
        obj.put("action", action)
        val logsKey = "logs"
        val logsRaw = auditPrefs.getString(logsKey, "") ?: ""
        val logsArr = if (logsRaw.isBlank()) JSONArray() else JSONArray("[$logsRaw]")
        logsArr.put(obj)
        auditPrefs.edit().putString(logsKey, logsArr.join(",")).apply()
    }

    // Exporta todos los logs en JSON firmado digitalmente
    fun exportSignedLogs(privateKey: PrivateKey): String {
        val logsRaw = auditPrefs.getString("logs", "") ?: ""
        val signature = signData(logsRaw, privateKey)
        val exportObj = JSONObject()
        exportObj.put("logs", JSONArray("[$logsRaw]"))
        exportObj.put("signature", signature)
        return exportObj.toString(2)
    }

    private fun signData(data: String, privateKey: PrivateKey): String {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(data.toByteArray())
        val signatureBytes = sig.sign()
        return Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    }
}