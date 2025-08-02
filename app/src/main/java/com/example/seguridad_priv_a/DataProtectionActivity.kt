package com.example.seguridad_priv_a

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.data.DataProtectionManager
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import java.util.concurrent.Executor

class DataProtectionActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy {
        (application as PermissionsApplication).dataProtectionManager
    }

    // Biometría
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var executor: Executor

    // Timeout de sesión (5 minutos)
    private var lastInteractionTime: Long = 0L
    private val sessionTimeoutMs = 5 * 60 * 1000L
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupBiometric()
        setupUI()
        loadDataProtectionInfo()
        requireAuthenticationForLogs()

        dataProtectionManager.logAccess("NAVIGATION", "DataProtectionActivity abierta")
    }

    private fun setupBiometric() {
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(
            this, // FragmentActivity
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    loadAccessLogs()
                    lastInteractionTime = System.currentTimeMillis()
                    Toast.makeText(
                        this@DataProtectionActivity,
                        "Autenticación exitosa",
                        Toast.LENGTH_SHORT
                    ).show()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    fallbackToPin()
                }

                override fun onAuthenticationFailed() {
                    fallbackToPin()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación Biométrica")
            .setSubtitle("Necesaria para ver logs de acceso")
            .setNegativeButtonText("Usar PIN/Patrón")
            .build()
    }

    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            requireAuthenticationForLogs()
        }

        binding.btnClearData.setOnClickListener {
            showClearDataDialog()
        }
    }

    private fun requireAuthenticationForLogs() {
        if (System.currentTimeMillis() - lastInteractionTime > sessionTimeoutMs) {
            biometricPrompt.authenticate(promptInfo)
        } else {
            loadAccessLogs()
        }
        lastInteractionTime = System.currentTimeMillis()
    }

    private fun fallbackToPin() {
        // Aquí podrías mostrar un diálogo real de PIN.
        AlertDialog.Builder(this)
            .setTitle("Introduce tu PIN")
            .setMessage("La autenticación biométrica ha fallado o no está disponible. Por favor, ingresa tu PIN para acceder a los logs.")
            .setPositiveButton("Ingresar PIN") { _, _ ->
                // Simulación: se acepta cualquier PIN, en app real verifica el PIN antes de mostrar logs
                loadAccessLogs()
                lastInteractionTime = System.currentTimeMillis()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun loadDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()
        val infoText = StringBuilder()

        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\n\n")
        info.forEach { (key, value) ->
            infoText.append("• $key: $value\n")
        }

        infoText.append("\n📊 EVIDENCIAS DE PROTECCIÓN:\n")
        infoText.append("• Encriptación AES-256-GCM activa\n")
        infoText.append("• Todos los accesos registrados\n")
        infoText.append("• Datos anonimizados automáticamente\n")
        infoText.append("• Almacenamiento local seguro\n")
        infoText.append("• No hay compartición de datos\n")

        binding.tvDataProtectionInfo.text = infoText.toString()
        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
    }

    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()
        binding.tvAccessLogs.text = if (logs.isNotEmpty()) {
            logs.joinToString("\n")
        } else {
            "No hay logs disponibles"
        }
        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }

    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados y logs de acceso? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun clearAllData() {
        dataProtectionManager.clearAllData()
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\n\nTodos los datos personales y logs han sido eliminados del dispositivo."
        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()
        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }

    override fun onResume() {
        super.onResume()
        if (System.currentTimeMillis() - lastInteractionTime > sessionTimeoutMs) {
            Toast.makeText(this, "Sesión expirada. Debes reautenticarte.", Toast.LENGTH_SHORT).show()
            requireAuthenticationForLogs()
        }
    }
}