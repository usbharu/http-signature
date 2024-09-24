package dev.usbharu.httpsignature.common

import java.time.Instant

data class SignatureParameters(
    val algorithm: String? = null,
    val keyId: String? = null,
    val created: Instant? = null,
    val expires: Instant? = null,
    val nonce: String? = null,
    val tag: String? = null,
) {
    fun toParameterList(): List<SignatureParameter> {
        return listOfNotNull(
            this.algorithm?.let { algorithm -> StringSignatureParameter("alg", algorithm) },
            this.keyId?.let { keyId -> StringSignatureParameter("keyid", keyId) },
            this.created?.let { created -> InstantSignatureParameter("created", created) },
            this.expires?.let { expires -> InstantSignatureParameter("expires", expires) },
            this.nonce?.let { nonce -> StringSignatureParameter("nonce", nonce) },
            this.tag?.let { tag -> StringSignatureParameter("tag", tag) },
        )
    }
}

