package com.example.seguridad_priv_a.data

class ForensicManager {
    // Chain of custody simple
    private val chainOfCustody = mutableListOf<String>()

    fun addEvidence(evidence: String, user: String) {
        chainOfCustody.add("${System.currentTimeMillis()}: $user añadió evidencia: $evidence")
    }

    // Blockchain local para logs
    private val logChain = mutableListOf<String>()
    fun addTamperEvidentLog(log: String) {
        val previous = logChain.lastOrNull() ?: ""
        val hash = (previous + log).hashCode().toString()
        logChain.add("$log|$hash")
    }

    // Reporte GDPA/CCPA simulado
    fun generateComplianceReport(): String {
        return "GDPR/CCPA Compliance Report\nTotal evidencias: ${chainOfCustody.size}\nTotal logs: ${logChain.size}"
    }

    // Herramientas de investigación de incidentes
    fun searchLogs(keyword: String): List<String> {
        return logChain.filter { it.contains(keyword) }
    }
}