package com.nexable.safecheck.core.platform.dns

import com.nexable.safecheck.core.domain.model.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.UnknownHostException
// Note: javax.naming is not available on Android runtime
// import javax.naming.Context
// import javax.naming.directory.InitialDirContext
// import javax.naming.directory.Attribute
import java.util.Hashtable

/**
 * Android implementation of DNS resolver using Java networking APIs.
 */
actual class DnsResolver {
    
    actual suspend fun resolveA(domain: String): Result<List<String>> {
        return withContext(Dispatchers.IO) {
            try {
                val addresses = InetAddress.getAllByName(domain)
                val ipv4Addresses = addresses
                    .filter { it.address.size == 4 } // IPv4 addresses are 4 bytes
                    .map { it.hostAddress }
                
                Result.success(ipv4Addresses)
            } catch (e: UnknownHostException) {
                Result.error("Failed to resolve A records for $domain: ${e.message}", "DNS_RESOLUTION_FAILED")
            } catch (e: Exception) {
                Result.error("DNS resolution error: ${e.message}", "DNS_ERROR")
            }
        }
    }
    
    actual suspend fun resolveAAAA(domain: String): Result<List<String>> {
        return withContext(Dispatchers.IO) {
            try {
                val addresses = InetAddress.getAllByName(domain)
                val ipv6Addresses = addresses
                    .filter { it.address.size == 16 } // IPv6 addresses are 16 bytes
                    .map { it.hostAddress }
                
                Result.success(ipv6Addresses)
            } catch (e: UnknownHostException) {
                Result.error("Failed to resolve AAAA records for $domain: ${e.message}", "DNS_RESOLUTION_FAILED")
            } catch (e: Exception) {
                Result.error("DNS resolution error: ${e.message}", "DNS_ERROR")
            }
        }
    }
    
    actual suspend fun resolveMX(domain: String): Result<List<MxRecord>> {
        return withContext(Dispatchers.IO) {
            try {
                val mxRecords = performDnsLookup(domain, "MX")
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
        return withContext(Dispatchers.IO) {
            try {
                val txtRecords = performDnsLookup(domain, "TXT")
                // Remove quotes from TXT records
                val cleanRecords = txtRecords.map { it.removeSurrounding("\"") }
                
                Result.success(cleanRecords)
            } catch (e: Exception) {
                Result.error("Failed to resolve TXT records for $domain: ${e.message}", "DNS_TXT_FAILED")
            }
        }
    }
    
    actual suspend fun resolveCNAME(domain: String): Result<String?> {
        return withContext(Dispatchers.IO) {
            try {
                val cnameRecords = performDnsLookup(domain, "CNAME")
                val cname = cnameRecords.firstOrNull()?.removeSuffix(".")
                
                Result.success(cname)
            } catch (e: Exception) {
                Result.error("Failed to resolve CNAME record for $domain: ${e.message}", "DNS_CNAME_FAILED")
            }
        }
    }
    
    actual suspend fun reverseResolve(ipAddress: String): Result<String?> {
        return withContext(Dispatchers.IO) {
            try {
                val address = InetAddress.getByName(ipAddress)
                val hostname = address.canonicalHostName
                
                // If canonical hostname is the same as IP, no reverse record exists
                val result = if (hostname != ipAddress) hostname else null
                
                Result.success(result)
            } catch (e: UnknownHostException) {
                Result.error("Failed to reverse resolve $ipAddress: ${e.message}", "DNS_REVERSE_FAILED")
            } catch (e: Exception) {
                Result.error("Reverse DNS resolution error: ${e.message}", "DNS_ERROR")
            }
        }
    }
    
    /**
     * Performs DNS lookup using Android-compatible methods.
     * Uses DNS-over-HTTPS for specialized record types that aren't available through InetAddress.
     */
    private suspend fun performDnsLookup(domain: String, recordType: String): List<String> {
        return withContext(Dispatchers.IO) {
            try {
                when (recordType) {
                    "MX" -> performMxLookup(domain)
                    "TXT" -> performTxtLookup(domain)
                    "CNAME" -> performCnameLookup(domain)
                    else -> emptyList()
                }
            } catch (e: Exception) {
                // Fallback to empty list if lookup fails
                emptyList()
            }
        }
    }
    
    /**
     * Performs MX record lookup using DNS-over-HTTPS.
     */
    private suspend fun performMxLookup(domain: String): List<String> {
        return try {
            val dohQuery = performDohQuery(domain, "MX")
            parseMxRecords(dohQuery)
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Performs TXT record lookup using DNS-over-HTTPS.
     */
    private suspend fun performTxtLookup(domain: String): List<String> {
        return try {
            val dohQuery = performDohQuery(domain, "TXT")
            parseTxtRecords(dohQuery)
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Performs CNAME record lookup using DNS-over-HTTPS.
     */
    private suspend fun performCnameLookup(domain: String): List<String> {
        return try {
            val dohQuery = performDohQuery(domain, "CNAME")
            parseCnameRecords(dohQuery)
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    /**
     * Performs DNS-over-HTTPS query to Cloudflare's public resolver.
     */
    private suspend fun performDohQuery(domain: String, recordType: String): String {
        return withContext(Dispatchers.IO) {
            try {
                val url = java.net.URL("https://cloudflare-dns.com/dns-query?name=$domain&type=$recordType")
                val connection = url.openConnection() as java.net.HttpURLConnection
                
                connection.requestMethod = "GET"
                connection.setRequestProperty("Accept", "application/dns-json")
                connection.setRequestProperty("User-Agent", "SafeCheck-Android/1.0")
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                
                val responseCode = connection.responseCode
                if (responseCode == 200) {
                    connection.inputStream.bufferedReader().use { reader ->
                        reader.readText()
                    }
                } else {
                    ""
                }
            } catch (e: Exception) {
                ""
            }
        }
    }
    
    /**
     * Parses MX records from DNS-over-HTTPS JSON response.
     */
    private fun parseMxRecords(jsonResponse: String): List<String> {
        return try {
            // Simple JSON parsing without external library
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
