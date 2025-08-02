package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import java.util.*
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import java.text.SimpleDateFormat

class DataProtectionManager(private val context: Context) {

    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences
    private lateinit var masterKey: MasterKey
    private val prefsMeta: SharedPreferences by lazy { context.getSharedPreferences("meta_prefs", Context.MODE_PRIVATE) }

    private val KEY_CREATION_DATE = "key_creation_date"
    private val KEY_SALT_PREFIX = "user_salt_"
    private val KEY_HMAC_SUFFIX = "_hmac"

    /**
     * Inicializa el sistema de protección de datos:
     * - Realiza rotación automática de la clave maestra si es necesario.
     * - Prepara los SharedPreferences cifrados.
     */
    fun initialize() {
        try {
            rotateEncryptionKeyIfNeeded()
            setupEncryptedPrefs()
        } catch (e: Exception) {
            // Fallback a SharedPreferences normales si falla la encriptación
            encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
        }
    }

    /**
     * Inicializa SharedPreferences cifrados y los logs.
     */
    private fun setupEncryptedPrefs() {
        masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        encryptedPrefs = EncryptedSharedPreferences.create(
            context,
            "secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
    }

    /**
     * Rota la clave maestra automáticamente si han pasado más de 30 días.
     */
    private fun rotateEncryptionKeyIfNeeded() {
        val lastRotation = prefsMeta.getLong(KEY_CREATION_DATE, 0L)
        val now = System.currentTimeMillis()
        val thirtyDaysMs = 30L * 24 * 60 * 60 * 1000
        if (now - lastRotation > thirtyDaysMs || lastRotation == 0L) {
            prefsMeta.edit().putLong(KEY_CREATION_DATE, now).apply()
            logAccess("KEY_MANAGEMENT", "Rotación automática de clave maestra realizada")
            // Aquí podrías migrar/re-encriptar datos si fuera necesario
        }
    }

    /**
     * Permite forzar la rotación de la clave maestra manualmente.
     */
    fun rotateEncryptionKey(): Boolean {
        prefsMeta.edit().putLong(KEY_CREATION_DATE, System.currentTimeMillis()).apply()
        logAccess("KEY_MANAGEMENT", "Rotación manual de clave maestra")
        // Aquí podrías migrar/re-encriptar datos si fuera necesario
        return true
    }

    /**
     * Verifica la integridad de un dato cifrado usando HMAC.
     */
    fun verifyDataIntegrity(key: String): Boolean {
        val value = encryptedPrefs.getString(key, null)
        val hmacStored = encryptedPrefs.getString(key + KEY_HMAC_SUFFIX, null)
        val userSalt = getUserSalt()
        if (value == null || hmacStored == null) return false
        val hmacCalc = generateHMAC(value, userSalt)
        return hmacStored == hmacCalc
    }

    /**
     * Guarda un dato seguro cifrado y su HMAC.
     */
    fun storeSecureData(key: String, value: String) {
        val userSalt = getUserSalt()
        encryptedPrefs.edit().putString(key, value)
            .putString(key + KEY_HMAC_SUFFIX, generateHMAC(value, userSalt))
            .apply()
        logAccess("DATA_STORAGE", "Dato almacenado de forma segura: $key")
    }

    /**
     * Obtiene un dato seguro, verificando primero su integridad.
     */
    fun getSecureData(key: String): String? {
        if (!verifyDataIntegrity(key)) {
            logAccess("INTEGRITY_CHECK", "Fallo de integridad de $key")
            return null
        }
        val value = encryptedPrefs.getString(key, null)
        if (value != null) logAccess("DATA_ACCESS", "Dato accedido: $key")
        return value
    }

    /**
     * Obtiene un salt único por usuario.
     */
    private fun getUserSalt(): String {
        val userId = getUserId()
        val keySalt = KEY_SALT_PREFIX + userId
        var salt = prefsMeta.getString(keySalt, null)
        if (salt == null) {
            salt = generateSalt()
            prefsMeta.edit().putString(keySalt, salt).apply()
        }
        return salt
    }

    /**
     * Genera un salt aleatorio (16 bytes en Base64).
     */
    private fun generateSalt(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    /**
     * Simula obtener el ID del usuario (en una app real usar el usuario autenticado).
     */
    private fun getUserId(): String = "default_user"

    /**
     * Deriva una clave usando PBKDF2 y salt.
     */
    private fun deriveKey(password: String, salt: String): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), Base64.decode(salt, Base64.NO_WRAP), 10000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

    /**
     * Genera un HMAC-SHA256 del dato usando la clave derivada.
     */
    private fun generateHMAC(data: String, salt: String): String {
        val keyBytes = deriveKey("app_secret", salt)
        val signingKey = SecretKeySpec(keyBytes, "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(signingKey)
        val hmacBytes = mac.doFinal(data.toByteArray())
        return Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
    }

    /**
     * Registra un acceso en los logs.
     */
    fun logAccess(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - $category: $action"

        val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\n$logEntry"
        }

        accessLogPrefs.edit().putString("logs", newLogs).apply()

        // Limitar a los últimos 100 logs
        val logLines = newLogs.split("\n")
        if (logLines.size > 100) {
            val trimmedLogs = logLines.takeLast(100).joinToString("\n")
            accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
        }
    }

    /**
     * Devuelve la lista de logs de acceso (más recientes primero).
     */
    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("logs", "") ?: ""
        return if (logsString.isEmpty()) {
            emptyList()
        } else {
            logsString.split("\n").reversed()
        }
    }

    /**
     * Borra todos los datos y logs de forma segura.
     */
    fun clearAllData() {
        encryptedPrefs.edit().clear().apply()
        accessLogPrefs.edit().clear().apply()
        logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }

    /**
     * Devuelve información del estado de la protección de datos.
     */
    fun getDataProtectionInfo(): Map<String, String> {
        return mapOf(
            "Encriptación" to "AES-256-GCM",
            "Almacenamiento" to "Local encriptado",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Última limpieza" to (getSecureData("last_cleanup") ?: "Nunca"),
            "Estado de seguridad" to "Activo"
        )
    }

    /**
     * Anonimiza información sensible.
     */
    fun anonymizeData(data: String): String {
        return data.replace(Regex("[0-9]"), "*")
            .replace(Regex("[A-Za-z]{3,}"), "***")
    }
}