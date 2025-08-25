package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.platform.tls.TlsAnalyzer

/**
 * URL unshortening utility that follows HTTP redirects.
 */
object UrlUnshortener {
    
    private const val MAX_REDIRECTS = 10
    
    /**
     * Follows HTTP redirects to get the final URL.
     * TODO: Implement actual HTTP HEAD request following redirects.
     */
    suspend fun unshorten(url: String): String {
        // For now, return the original URL
        // In a real implementation, this would:
        // 1. Make HTTP HEAD request to the URL
        // 2. Check for Location header in 3xx responses
        // 3. Follow redirects up to MAX_REDIRECTS
        // 4. Return the final URL
        return url
    }
    
    /**
     * Gets the redirect chain for a URL.
     */
    suspend fun getRedirectChain(url: String): List<String> {
        // TODO: Implement redirect chain tracking
        return listOf(url)
    }
}

/**
 * HTTPS analysis utilities.
 */
object HttpsAnalyzer {
    
    /**
     * Analyzes HTTPS support and security for a URL.
     */
    suspend fun analyze(url: String, tlsAnalyzer: TlsAnalyzer): HttpsAnalysis {
        val supportsHttps = url.startsWith("https://")
        val httpsUrl = if (supportsHttps) url else url.replace("http://", "https://")
        
        // Check if HTTPS is available
        val domain = UrlParser.extractDomain(url)
        val httpsAvailable = if (!supportsHttps) {
            when (val result = tlsAnalyzer.isHttpsAvailable(httpsUrl)) {
                is com.nexable.safecheck.core.domain.model.Result.Success -> result.data
                else -> false
            }
        } else true
        
        return HttpsAnalysis(
            originalUrl = url,
            supportsHttps = supportsHttps,
            httpsAvailable = httpsAvailable,
            redirectsToHttps = httpsAvailable && !supportsHttps,
            httpsUrl = if (httpsAvailable) httpsUrl else null
        )
    }
}
