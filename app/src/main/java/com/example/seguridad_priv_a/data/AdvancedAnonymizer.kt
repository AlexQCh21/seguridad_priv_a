package com.example.seguridad_priv_a.data

class AdvancedAnonymizer {
    // k-anonymity: solo retorna registros si hay al menos k idénticos en los atributos quasi-identificadores
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData> {
        val grouped = data.groupBy { it.quasiIdentifiers() }
        return grouped.filter { it.value.size >= k }
            .flatMap { group -> group.value.map { it.anonymize() } }
    }

    // Differential privacy: agrega ruido Laplaciano a un valor numérico
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData {
        val noise = laplaceNoise(0.0, 1.0/epsilon)
        return data.copy(value = data.value + noise)
    }

    // Data masking según tipo
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any {
        return when (data) {
            is String -> maskingPolicy.maskString(data)
            is Number -> maskingPolicy.maskNumber(data)
            else -> data
        }
    }

    // Ejemplo de políticas de retención
    fun shouldRetainData(data: Any, policy: RetentionPolicy): Boolean {
        return policy.isRetentionValid()
    }

    private fun laplaceNoise(mu: Double, b: Double): Double {
        val u = Math.random() - 0.5
        return mu - b * Math.signum(u) * Math.log(1 - 2 * Math.abs(u))
    }
}

// Ejemplos de clases auxiliares:
data class PersonalData(val name: String, val age: Int, val city: String) {
    fun quasiIdentifiers() = "$age|$city"
    fun anonymize() = AnonymizedData("***", age, city)
}
data class AnonymizedData(val name: String, val age: Int, val city: String)
data class NumericData(val value: Double)
interface MaskingPolicy {
    fun maskString(data: String): String
    fun maskNumber(data: Number): Number
}
interface RetentionPolicy {
    fun isRetentionValid(): Boolean
}