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
