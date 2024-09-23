package dev.usbharu.httpsignature.v2

import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PSSParameterSpec
import java.util.*

open class RsaPssSignatureSigner(private val pssParameterSpec: PSSParameterSpec) : SignatureSigner {
    override fun sign(byteArray: ByteArray, privateKey: PrivateKey): String {
        val signature = Signature.getInstance("RSASSA-PSS")
        signature.setParameter(pssParameterSpec)
        signature.initSign(privateKey)
        signature.update(byteArray)
        return Base64.getEncoder().encodeToString(signature.sign())
    }
}