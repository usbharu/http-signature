package dev.usbharu.httpsignature.common

import java.security.PrivateKey
import java.security.PublicKey


sealed class Key(open val keyId: String)

data class PrivateKey(val privateKey: PrivateKey, override val keyId: String) : Key(keyId)
data class PublicKey(val publicKey: PublicKey, override val keyId: String) : Key(keyId)
