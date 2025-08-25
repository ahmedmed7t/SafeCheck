package com.nexable.safecheck.core.platform.dns

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.*
import platform.Network.*
import kotlin.coroutines.resume

/**
 * iOS implementation of DNS resolver using Network framework and Foundation APIs.
 */
actual class DnsResolver {
    
    actual suspend fun resolveA(domain: String): Result<List<String>> {
        return withContext(Dispatchers.Default) {
            try {
                val addresses = resolveHostname(domain)
                val ipv4Addresses = addresses.filter { address ->
                    // Check if it's IPv4 (no colons, has dots)
                    address.contains(".") && !address.contains(":")
                }
                
                Result.success(ipv4Addresses)
            } catch (e: Exception) {
                Result.error("Failed to resolve A records for $domain: ${e.message}", "DNS_RESOLUTION_FAILED")
            }
        }
    }
    
    actual suspend fun resolveAAAA(domain: String): Result<List<String>> {
        return withContext(Dispatchers.Default) {
            try {
                val addresses = resolveHostname(domain)
                val ipv6Addresses = addresses.filter { address ->
                    // Check if it's IPv6 (contains colons)
                    address.contains(":")
                }
                
                Result.success(ipv6Addresses)
            } catch (e: Exception) {
                Result.error("Failed to resolve AAAA records for $domain: ${e.message}", "DNS_RESOLUTION_FAILED")
            }
        }
    }
    
    actual suspend fun resolveMX(domain: String): Result<List<MxRecord>> {
        return withContext(Dispatchers.Default) {
            try {
                val mxRecords = performDnsQuery(domain, "MX")
                val records = mxRecords.mapNotNull { record ->
                    val parts = record.split(" ")
                    if (parts.size >= 2) {
                        val priority = parts[0].toIntOrNull() ?: 0
                        val host = parts[1].removeSuffix(".")
                        MxRecord(host, priority)
                    } else null
                }
                
                Result.success(records)
            } catch (e: Exception) {
                Result.error("Failed to resolve MX records for $domain: ${e.message}", "DNS_MX_FAILED")
            }
        }
    }
    
    actual suspend fun resolveTXT(domain: String): Result<List<String>> {
        return withContext(Dispatchers.Default) {
            try {
                val txtRecords = performDnsQuery(domain, "TXT")
                // Remove quotes from TXT records
                val cleanRecords = txtRecords.map { it.removeSurrounding("\"") }
                
                Result.success(cleanRecords)
            } catch (e: Exception) {
                Result.error("Failed to resolve TXT records for $domain: ${e.message}", "DNS_TXT_FAILED")
            }
        }
    }
    
    actual suspend fun resolveCNAME(domain: String): Result<String?> {
        return withContext(Dispatchers.Default) {
            try {
                val cnameRecords = performDnsQuery(domain, "CNAME")
                val cname = cnameRecords.firstOrNull()?.removeSuffix(".")
                
                Result.success(cname)
            } catch (e: Exception) {
                Result.error("Failed to resolve CNAME record for $domain: ${e.message}", "DNS_CNAME_FAILED")
            }
        }
    }
    
    actual suspend fun reverseResolve(ipAddress: String): Result<String?> {
        return withContext(Dispatchers.Default) {
            try {
                val hostname = performReverseDnsLookup(ipAddress)
                Result.success(hostname)
            } catch (e: Exception) {
                Result.error("Failed to reverse resolve $ipAddress: ${e.message}", "DNS_REVERSE_FAILED")
            }
        }
    }
    
    /**
     * Resolves hostname to IP addresses using iOS Foundation APIs.
     */
    private suspend fun resolveHostname(hostname: String): List<String> {
        return suspendCancellableCoroutine { continuation ->
            try {
                val host = NSHost.hostWithName(hostname)
                val addresses = host?.addresses ?: emptyList<String>()
                
                continuation.resume(addresses)
            } catch (e: Exception) {
                continuation.resume(emptyList())
            }
        }
    }
    
    /**
     * Performs DNS query using DNS-over-HTTPS for specialized record types.
     */
    private suspend fun performDnsQuery(domain: String, recordType: String): List<String> {
        return suspendCancellableCoroutine { continuation ->
            try {
                val urlString = "https://cloudflare-dns.com/dns-query?name=$domain&type=$recordType"
                val url = NSURL.URLWithString(urlString)
                
                if (url == null) {
                    continuation.resume(emptyList())
                    return@suspendCancellableCoroutine
                }
                
                val request = NSMutableURLRequest.requestWithURL(url)
                request.setValue("application/dns-json", forHTTPHeaderField = "Accept")
                request.setValue("SafeCheck-iOS/1.0", forHTTPHeaderField = "User-Agent")
                request.setTimeoutInterval(10.0)
                
                val session = NSURLSession.sharedSession
                val task = session.dataTaskWithRequest(request) { data, response, error ->
                    if (error != null) {
                        continuation.resume(emptyList())
                        return@dataTaskWithRequest
                    }
                    
                    if (data == null) {
                        continuation.resume(emptyList())
                        return@dataTaskWithRequest
                    }
                    
                    val responseString = NSString.create(data, NSUTF8StringEncoding)?.toString()
                    if (responseString != null) {
                        val records = parseDnsResponse(responseString, recordType)
                        continuation.resume(records)
                    } else {
                        continuation.resume(emptyList())
                    }
                }
                
                task.resume()
            } catch (e: Exception) {
                continuation.resume(emptyList())
            }
        }
    }
    
    /**
     * Performs reverse DNS lookup using Foundation APIs.
     */
    private suspend fun performReverseDnsLookup(ipAddress: String): String? {
        return suspendCancellableCoroutine { continuation ->
            try {
                val host = NSHost.hostWithAddress(ipAddress)
                val hostname = host?.name
                
                // If hostname is the same as IP, no reverse record exists
                val result = if (hostname != ipAddress) hostname else null
                continuation.resume(result)
            } catch (e: Exception) {
                continuation.resume(null)
            }
        }
    }
    
    /**
     * Parses DNS-over-HTTPS JSON response.
     */
    private fun parseDnsResponse(jsonResponse: String, recordType: String): List<String> {
        return try {
            when (recordType) {
                "MX" -> parseMxRecords(jsonResponse)
                "TXT" -> parseTxtRecords(jsonResponse)
                "CNAME" -> parseCnameRecords(jsonResponse)
                else -> emptyList()
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Parses MX records from DNS-over-HTTPS JSON response.
     */
    private fun parseMxRecords(jsonResponse: String): List<String> {
        return try {
            val answers = extractAnswersFromJson(jsonResponse)
            answers.mapNotNull { answer ->
                val dataMatch = Regex("\"data\"\\s*:\\s*\"([^\"]+)\"").find(answer)
                dataMatch?.groupValues?.get(1)
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Parses TXT records from DNS-over-HTTPS JSON response.
     */
    private fun parseTxtRecords(jsonResponse: String): List<String> {
        return try {
            val answers = extractAnswersFromJson(jsonResponse)
            answers.mapNotNull { answer ->
                val dataMatch = Regex("\"data\"\\s*:\\s*\"([^\"]+)\"").find(answer)
                dataMatch?.groupValues?.get(1)?.removeSurrounding("\"")
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Parses CNAME records from DNS-over-HTTPS JSON response.
     */
    private fun parseCnameRecords(jsonResponse: String): List<String> {
        return try {
            val answers = extractAnswersFromJson(jsonResponse)
            answers.mapNotNull { answer ->
                val dataMatch = Regex("\"data\"\\s*:\\s*\"([^\"]+)\"").find(answer)
                dataMatch?.groupValues?.get(1)?.removeSuffix(".")
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Extracts answer objects from DNS-over-HTTPS JSON response.
     */
    private fun extractAnswersFromJson(jsonResponse: String): List<String> {
        return try {
            val answersMatch = Regex("\"Answer\"\\s*:\\s*\\[([^\\]]+)\\]").find(jsonResponse)
            val answersContent = answersMatch?.groupValues?.get(1) ?: return emptyList()
            
            // Split by objects (simple approach)
            val answers = mutableListOf<String>()
            var braceCount = 0
            var currentAnswer = StringBuilder()
            
            for (char in answersContent) {
                when (char) {
                    '{' -> {
                        if (braceCount == 0) currentAnswer.clear()
                        braceCount++
                        currentAnswer.append(char)
                    }
                    '}' -> {
                        braceCount--
                        currentAnswer.append(char)
                        if (braceCount == 0) {
                            answers.add(currentAnswer.toString())
                        }
                    }
                    else -> currentAnswer.append(char)
                }
            }
            
            answers
        } catch (e: Exception) {
            emptyList()
        }
    }
}
