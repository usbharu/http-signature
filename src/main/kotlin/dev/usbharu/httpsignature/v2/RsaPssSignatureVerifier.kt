package dev.usbharu.httpsignature.v2

import java.security.PublicKey
import java.security.Signature
import java.security.spec.PSSParameterSpec

open class RsaPssSignatureVerifier(private val pssParameterSpec: PSSParameterSpec) : SignatureVerifier {
    override fun verify(byteArray: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        val verifier = Signature.getInstance("RSASSA-PSS")
        verifier.setParameter(pssParameterSpec)
        verifier.initVerify(publicKey)
        verifier.update(byteArray)
        return verifier.verify(signature)
    }
}