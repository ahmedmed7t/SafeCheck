package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Result
import com.nexable.safecheck.core.platform.dns.DnsResolver
import com.nexable.safecheck.core.platform.whois.WhoisClient
import com.nexable.safecheck.core.platform.tls.TlsAnalyzer
import kotlinx.datetime.Clock

/**
 * TLS certificate analyzer using platform TLS implementation.
 */
object TlsCertificateAnalyzer {
    
    /**
     * Analyzes TLS certificate for a domain.
     */
    suspend fun analyze(domain: String, tlsAnalyzer: TlsAnalyzer): TlsCertificateAnalysis {
        return when (val result = tlsAnalyzer.analyzeCertificate(domain, 443)) {
            is Result.Success -> {
                val analysis = result.data
                TlsCertificateAnalysis(
                    domain = domain,
                    hasValidCertificate = analysis.hasValidCertificate,
                    certificateInfo = analysis.certificate,
                    daysUntilExpiry = analysis.certificate?.daysUntilExpiry ?: 0,
                    isExpired = analysis.certificate?.isExpired ?: false,
                    isExpiringSoon = analysis.certificate?.isExpiringSoon ?: false,
                    securityIssues = analysis.securityIssues,
                    tlsVersion = analysis.tlsVersion ?: "Unknown"
                )
            }
            is Result.Error -> {
                TlsCertificateAnalysis(
                    domain = domain,
                    hasValidCertificate = false,
                    certificateInfo = null,
                    daysUntilExpiry = 0,
                    isExpired = true,
                    isExpiringSoon = false,
                    securityIssues = emptyList(),
                    tlsVersion = "Unknown",
                    error = result.message
                )
            }
            is Result.Loading -> {
                TlsCertificateAnalysis(
                    domain = domain,
                    hasValidCertificate = false,
                    certificateInfo = null,
                    daysUntilExpiry = 0,
                    isExpired = false,
                    isExpiringSoon = false,
                    securityIssues = emptyList(),
                    tlsVersion = "Unknown",
                    error = "Analysis in progress"
                )
            }
        }
    }
}

/**
 * WHOIS analyzer using platform WHOIS implementation.
 */
object WhoisAnalyzer {
    
    /**
     * Analyzes WHOIS information for domain age and registration details.
     */
    suspend fun analyze(domain: String, whoisClient: WhoisClient): WhoisDomainAnalysis {
        return when (val result = whoisClient.lookup(domain)) {
            is Result.Success -> {
                val whoisInfo = result.data
                WhoisDomainAnalysis(
                    domain = domain,
                    ageDays = whoisInfo.ageDays,
                    isExpired = whoisInfo.isExpired,
                    daysTillExpiry = whoisInfo.daysTillExpiry,
                    registrar = whoisInfo.registrar,
                    isPrivacyProtected = whoisInfo.isPrivacyProtected,
                    registrantCountry = whoisInfo.registrantCountry
                )
            }
            is Result.Error -> {
                WhoisDomainAnalysis(
                    domain = domain,
                    ageDays = 0,
                    isExpired = false,
                    daysTillExpiry = null,
                    registrar = null,
                    isPrivacyProtected = false,
                    registrantCountry = null,
                    error = result.message
                )
            }
            is Result.Loading -> {
                WhoisDomainAnalysis(
                    domain = domain,
                    ageDays = 0,
                    isExpired = false,
                    daysTillExpiry = null,
                    registrar = null,
                    isPrivacyProtected = false,
                    registrantCountry = null,
                    error = "Analysis in progress"
                )
            }
        }
    }
}

/**
 * DNS analyzer using platform DNS implementation.
 */
object DnsAnalyzer {
    
    /**
     * Analyzes DNS records for a domain.
     */
    suspend fun analyze(domain: String, dnsResolver: DnsResolver): DnsRecordAnalysis {
        val aRecords = when (val result = dnsResolver.resolveA(domain)) {
            is Result.Success -> result.data
            else -> emptyList()
        }
        
        val aaaaRecords = when (val result = dnsResolver.resolveAAAA(domain)) {
            is Result.Success -> result.data
            else -> emptyList()
        }
        
        val mxRecords = when (val result = dnsResolver.resolveMX(domain)) {
            is Result.Success -> result.data
            else -> emptyList()
        }
        
        val txtRecords = when (val result = dnsResolver.resolveTXT(domain)) {
            is Result.Success -> result.data
            else -> emptyList()
        }
        
        return DnsRecordAnalysis(
            domain = domain,
            hasARecords = aRecords.isNotEmpty(),
            hasAAAARecords = aaaaRecords.isNotEmpty(),
            hasMxRecords = mxRecords.isNotEmpty(),
            aRecords = aRecords,
            aaaaRecords = aaaaRecords,
            mxRecords = mxRecords.map { "${it.priority} ${it.host}" },
            txtRecords = txtRecords,
            hasSpfRecord = txtRecords.any { it.startsWith("v=spf1") },
            hasDmarcRecord = txtRecords.any { it.startsWith("v=DMARC1") }
        )
    }
}
