package com.nexable.safecheck.core.platform.tls

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*
import kotlin.time.measureTime

/**
 * Android implementation of TLS analyzer using Java SSL APIs.
 */
actual class TlsAnalyzer {
    
    companion object {
        private const val CONNECTION_TIMEOUT = 10000 // 10 seconds
        private val WEAK_CIPHERS = setOf(
            "SSL_RSA_WITH_DES_CBC_SHA",
            "SSL_DHE_RSA_WITH_DES_CBC_SHA",
            "SSL_RSA_WITH_RC4_128_MD5",
            "SSL_RSA_WITH_RC4_128_SHA"
        )
        
        private val WEAK_TLS_VERSIONS = setOf("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
    }
    
    actual suspend fun analyzeCertificate(hostname: String, port: Int): Result<TlsAnalysis> {
        return withContext(Dispatchers.IO) {
            try {
                val startTime = System.currentTimeMillis()
                
                val socketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                var socket: SSLSocket? = null
                
                try {
                    socket = socketFactory.createSocket(hostname, port) as SSLSocket
                    socket.soTimeout = CONNECTION_TIMEOUT
                    
                    // Perform TLS handshake
                    socket.startHandshake()
                    
                    val connectionTime = System.currentTimeMillis() - startTime
                    val session = socket.session
                    val certificates = session.peerCertificates
                    
                    val certificateInfo = if (certificates.isNotEmpty()) {
                        val cert = certificates[0] as X509Certificate
                        parseCertificate(cert, hostname)
                    } else null
                    
                    val securityIssues = mutableListOf<SecurityIssue>()
                    
                    // Check for security issues
                    certificateInfo?.let { certInfo ->
                        if (certInfo.isExpired) {
                            securityIssues.add(SecurityIssue(
                                type = SecurityIssueType.EXPIRED_CERTIFICATE,
                                severity = Severity.CRITICAL,
                                description = "Certificate has expired"
                            ))
                        }
                        
                        if (certInfo.isExpiringSoon) {
                            securityIssues.add(SecurityIssue(
                                type = SecurityIssueType.EXPIRED_CERTIFICATE,
                                severity = Severity.MEDIUM,
                                description = "Certificate expires in ${certInfo.daysUntilExpiry} days"
                            ))
                        }
                        
                        if (certInfo.keySize < 2048) {
                            securityIssues.add(SecurityIssue(
                                type = SecurityIssueType.WEAK_KEY_SIZE,
                                severity = Severity.HIGH,
                                description = "Weak key size: ${certInfo.keySize} bits"
                            ))
                        }
                        
                        if (certInfo.isSelfSigned) {
                            securityIssues.add(SecurityIssue(
                                type = SecurityIssueType.SELF_SIGNED_CERTIFICATE,
                                severity = Severity.HIGH,
                                description = "Certificate is self-signed"
                            ))
                        }
                    }
                    
                    val protocol = session.protocol
                    val cipherSuite = session.cipherSuite
                    
                    if (protocol in WEAK_TLS_VERSIONS) {
                        securityIssues.add(SecurityIssue(
                            type = SecurityIssueType.OUTDATED_TLS_VERSION,
                            severity = Severity.HIGH,
                            description = "Weak TLS version: $protocol"
                        ))
                    }
                    
                    if (cipherSuite in WEAK_CIPHERS) {
                        securityIssues.add(SecurityIssue(
                            type = SecurityIssueType.WEAK_CIPHER,
                            severity = Severity.HIGH,
                            description = "Weak cipher suite: $cipherSuite"
                        ))
                    }
                    
                    val analysis = TlsAnalysis(
                        hostname = hostname,
                        port = port,
                        hasValidCertificate = certificateInfo != null && !certificateInfo.isExpired,
                        certificate = certificateInfo,
                        tlsVersion = protocol,
                        cipherSuite = cipherSuite,
                        supportedVersions = listOf(protocol), // Would need separate connection to get all
                        securityIssues = securityIssues,
                        connectionTimeMs = connectionTime,
                        certificateChainLength = certificates.size,
                        isExtendedValidation = false, // Would need to check certificate policies
                        supportsHSTS = false, // Would need HTTP header check
                        supportsSNI = true // Assume modern servers support SNI
                    )
                    
                    Result.success(analysis)
                    
                } finally {
                    socket?.close()
                }
                
            } catch (e: IOException) {
                Result.error("TLS connection failed: ${e.message}", "TLS_CONNECTION_FAILED")
            } catch (e: Exception) {
                Result.error("TLS analysis failed: ${e.message}", "TLS_ANALYSIS_FAILED")
            }
        }
    }
    
    actual suspend fun isHttpsAvailable(url: String): Result<Boolean> {
        return withContext(Dispatchers.IO) {
            try {
                val hostname = extractHostname(url)
                val result = analyzeCertificate(hostname, 443)
                
                when (result) {
                    is Result.Success -> Result.success(true)
                    is Result.Error -> Result.success(false)
                    is Result.Loading -> Result.success(false)
                }
            } catch (e: Exception) {
                Result.success(false)
            }
        }
    }
    
    actual suspend fun getSupportedTlsVersions(hostname: String, port: Int): Result<List<String>> {
        return withContext(Dispatchers.IO) {
            try {
                val supportedVersions = mutableListOf<String>()
                val versionsToTest = listOf("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1")
                
                for (version in versionsToTest) {
                    if (testTlsVersion(hostname, port, version)) {
                        supportedVersions.add(version)
                    }
                }
                
                Result.success(supportedVersions)
            } catch (e: Exception) {
                Result.error("Failed to test TLS versions: ${e.message}", "TLS_VERSION_TEST_FAILED")
            }
        }
    }
    
    private fun parseCertificate(cert: X509Certificate, hostname: String): CertificateInfo {
        val subjectDN = cert.subjectDN.name
        val issuerDN = cert.issuerDN.name
        val serialNumber = cert.serialNumber.toString(16)
        val algorithm = cert.sigAlgName
        val keySize = getKeySize(cert)
        val validFrom = Instant.fromEpochMilliseconds(cert.notBefore.time)
        val validTo = Instant.fromEpochMilliseconds(cert.notAfter.time)
        val fingerprint = generateFingerprint(cert)
        
        val sanList = mutableListOf<String>()
        try {
            cert.subjectAlternativeNames?.forEach { san ->
                val sanValue = san[1] as? String
                if (sanValue != null) {
                    sanList.add(sanValue)
                }
            }
        } catch (e: Exception) {
            // Ignore SAN parsing errors
        }
        
        val isSelfSigned = cert.issuerDN == cert.subjectDN
        val isWildcard = subjectDN.contains("*.") || sanList.any { it.startsWith("*.") }
        
        return CertificateInfo(
            subject = subjectDN,
            issuer = issuerDN,
            serialNumber = serialNumber,
            algorithm = algorithm,
            keySize = keySize,
            validFrom = validFrom,
            validTo = validTo,
            fingerprint = fingerprint,
            subjectAlternativeNames = sanList,
            isSelfSigned = isSelfSigned,
            isWildcard = isWildcard,
            version = cert.version
        )
    }
    
    private fun getKeySize(cert: X509Certificate): Int {
        return try {
            val publicKey = cert.publicKey
            when (publicKey.algorithm) {
                "RSA" -> {
                    val rsaKey = publicKey as java.security.interfaces.RSAPublicKey
                    rsaKey.modulus.bitLength()
                }
                "EC" -> {
                    val ecKey = publicKey as java.security.interfaces.ECPublicKey
                    ecKey.params.order.bitLength()
                }
                else -> 0
            }
        } catch (e: Exception) {
            0
        }
    }
    
    private fun generateFingerprint(cert: X509Certificate): String {
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val digest = md.digest(cert.encoded)
            digest.joinToString(":") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }
    
    private fun testTlsVersion(hostname: String, port: Int, version: String): Boolean {
        return try {
            val context = SSLContext.getInstance(version)
            context.init(null, null, null)
            
            val socket = context.socketFactory.createSocket(hostname, port) as SSLSocket
            socket.soTimeout = 5000
            socket.startHandshake()
            socket.close()
            true
        } catch (e: Exception) {
            false
        }
    }
    
    private fun extractHostname(url: String): String {
        return try {
            val withoutProtocol = url.removePrefix("https://").removePrefix("http://")
            val hostname = withoutProtocol.split("/")[0].split(":")[0]
            hostname
        } catch (e: Exception) {
            url
        }
    }
    
    /**
     * Verification function to ensure kotlinx-datetime imports work correctly.
     * This demonstrates that Clock and Instant are properly imported and accessible.
     */
    private fun verifyDateTimeImports(): String {
        val now = Clock.System.now()
        val epochTime = now.toEpochMilliseconds()
        return "kotlinx-datetime imports working in TlsAnalyzer: Current time is $epochTime"
    }
}
