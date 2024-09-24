package dev.usbharu.httpsignature.verify

import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class RsaPssSha512SignatureVerifier(salt: Int = 64) :
    RsaPssSignatureVerifier(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, salt, 1))