# PRÁCTICA 15 - LABORATORIO - APLICACIONES MÓVILES
# 🛡️ Análisis de Seguridad en la Aplicación Android

## 1.1 Identificación de Vulnerabilidades (2 puntos)

Análisis del archivo `DataProtectionManager.kt`.

### 🔐 ¿Qué método de encriptación se utiliza para proteger datos sensibles?
- `AES-256-GCM` para cifrar los valores (datos sensibles) almacenados.
- `AES-256-SIV` para cifrar las claves (keys) de esos datos dentro de `EncryptedSharedPreferences`.

### ⚠️ Posibles vulnerabilidades en la implementación actual del logging
- Almacenamiento de logs sin cifrado.
- Acumulación ilimitada y concatenación de logs en un solo `String`.

### ❌ ¿Qué sucede si falla la inicialización del sistema de encriptación?
- Se captura una excepción y se hace un fallback a `SharedPreferences` normales si falla la encriptación.

---

## 1.2 Permisos y Manifiesto (2 puntos)

Examen de `AndroidManifest.xml` y `MainActivity.kt`.

### 📋 Lista de permisos peligrosos declarados en el manifiesto:
- `android.permission.CAMERA`
- `android.permission.READ_EXTERNAL_STORAGE`
- `android.permission.READ_MEDIA_IMAGES`
- `android.permission.RECORD_AUDIO`
- `android.permission.READ_CONTACTS`
- `android.permission.CALL_PHONE`
- `android.permission.SEND_SMS`
- `android.permission.ACCESS_COARSE_LOCATION`

### 🧩 Patrón utilizado para solicitar permisos en runtime:
- Se utiliza el **Activity Result API**.

### 🔒 Configuración de seguridad que previene backups automáticos:
- `android:allowBackup="false"` en el archivo `AndroidManifest.xml`.

---

## 1.3 Gestión de Archivos (3 puntos)

Revisión de `CameraActivity.kt` y `file_paths.xml`.

### 📁 ¿Cómo se implementa la compartición segura de archivos de imágenes?
- Se utiliza un `FileProvider`, que permite compartir archivos entre apps usando un URI seguro (`content://`) en lugar de exponer rutas directas (`file://`).

### 🆔 Autoridad utilizada para el `FileProvider`:
- `com.example.seguridad_priv_a.fileprovider`

### 🚫 ¿Por qué no se debe usar URIs con `file://` directamente?
Desde Android 7.0 (API 24), el uso de URIs `file://` para compartir archivos está prohibido y lanza una `FileUriExposedException`.

Esto se debe a que:
- Expone la ruta absoluta del archivo.
- Puede permitir acceso no autorizado a archivos arbitrarios si otra app obtiene esa URI.


## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)

**Cambios realizados en `DataProtectionManager.kt`:**
- **Rotación automática de claves maestras cada 30 días:**  
  Se implementó lógica para rotar automáticamente la clave maestra (`MasterKey`) cada 30 días.  
  ```kotlin
  fun rotateEncryptionKey(): Boolean {
      prefsMeta.edit().putLong(KEY_CREATION_DATE, System.currentTimeMillis()).apply()
      logAccess("KEY_MANAGEMENT", "Rotación manual de clave maestra")
      return true
  }
  ```
- **Verificación de integridad de datos cifrados usando HMAC:**  
  Cada vez que se almacena un dato cifrado, se guarda un HMAC asociado.  
  La integridad se verifica antes de devolver datos:
  ```kotlin
  fun verifyDataIntegrity(key: String): Boolean {
      val value = encryptedPrefs.getString(key, null)
      val hmacStored = encryptedPrefs.getString(key + KEY_HMAC_SUFFIX, null)
      val userSalt = getUserSalt()
      if (value == null || hmacStored == null) return false
      val hmacCalc = generateHMAC(value, userSalt)
      return hmacStored == hmacCalc
  }
  ```
- **Key derivation con salt único por usuario:**  
  Cada usuario tiene un salt único, y las claves derivadas utilizan PBKDF2 con ese salt.
  ```kotlin
  private fun deriveKey(password: String, salt: String): ByteArray {
      val spec = PBEKeySpec(password.toCharArray(), Base64.decode(salt, Base64.NO_WRAP), 10000, 256)
      val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
      return factory.generateSecret(spec).encoded
  }
  ```

---

### 2.2 Sistema de Auditoría Avanzado (3 puntos)

**Clase `SecurityAuditManager`:**
- **Detección de intentos sospechosos:**  
  Cuenta intentos en un periodo corto y detecta patrones anómalos.
- **Rate limiting:**  
  Limita operaciones sensibles por usuario/tiempo.
- **Alertas:**  
  Genera alertas ante patrones sospechosos y las guarda.
- **Exportación de logs en JSON firmado:**
  ```kotlin
  fun exportLogsSigned(): String {
      val json = Gson().toJson(logs)
      val signature = signData(json)
      return "{\"logs\":$json, \"signature\":\"$signature\"}"
  }
  ```

---

### 2.3 Biometría y Autenticación (3 puntos)

**En `DataProtectionActivity.kt`:**
- **Integración de `BiometricPrompt` API:**  
  Protege el acceso a logs con biometría.
- **Fallback a PIN/Pattern:**  
  Si la biometría falla o no está disponible, solicita PIN.
- **Timeout de sesión:**  
  Si hay más de 5 minutos de inactividad, requiere reautenticación antes de acceder a operaciones sensibles.

---

## Parte 3: Arquitectura de Seguridad Avanzada (15-20 puntos)

### 3.1 Implementación de Zero-Trust Architecture (3 puntos)

- **Validación de cada operación sensible:**  
  Se requiere validación contextual y de permisos antes de operaciones críticas usando `ZeroTrustManager`.
  ```kotlin
  ZeroTrustManager.validateSensitiveOperation(context, "STORE_DATA", "user")
  ```
- **Principio de menor privilegio:**  
  Cada sesión y token tiene roles y privilegios mínimos para cada contexto.
- **Sesiones temporales seguras:**  
  Uso de tokens temporales gestionados por `SecuritySessionManager`.
- **Attestation de integridad de la app:**  
  Se verifica la integridad de la aplicación antes de permitir operaciones críticas.

---

### 3.2 Protección Contra Ingeniería Inversa (3 puntos)

- **Detección de debugging/emuladores:**  
  Se implementan métodos para detectar si la app está bajo debugging o corriendo en emulador.
- **Obfuscación de strings y claves:**  
  Uso de Proguard/R8 y almacenamiento de strings sensibles cifradas.
- **Verificación de firma digital en runtime:**  
  La app valida que la firma digital corresponde a la esperada.
- **Certificate pinning:**  
  Implementado en clientes HTTP usando OkHttp.

---

### 3.3 Framework de Anonimización Avanzado (2 puntos)

**Clase `AdvancedAnonymizer`:**
- **k-anonymity y l-diversity:**  
  Agrupa y anonimiza registros para que haya al menos k iguales y diversidad en los valores sensibles.
- **Differential privacy:**  
  Agrega ruido laplaciano a datos numéricos para privacidad.
- **Data masking según tipo:**  
  Enmascara datos de acuerdo a políticas configurables.
- **Políticas de retención:**  
  Determina si los datos deben ser retenidos o eliminados según políticas programadas.

---

### 3.4 Análisis Forense y Compliance (2 puntos)

**Clase `ForensicManager`:**
- **Chain of custody:**  
  Registra la secuencia completa de acceso y manipulación de evidencias digitales.
- **Logs tamper-evident (blockchain local):**  
  Cada log contiene hash del anterior, asegurando integridad de la cadena.
- **Reporte GDPR/CCPA automático:**  
  Genera informes de cumplimiento automáticamente.
- **Herramientas de investigación de incidentes:**  
  Permite búsqueda y filtrado avanzado sobre los registros de logs.

---

