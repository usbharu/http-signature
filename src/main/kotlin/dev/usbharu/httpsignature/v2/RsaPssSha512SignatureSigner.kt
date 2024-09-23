package dev.usbharu.httpsignature.v2

import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class RsaPssSha512SignatureSigner(salt: Int = 64) :
    RsaPssSignatureSigner(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, salt, 1))