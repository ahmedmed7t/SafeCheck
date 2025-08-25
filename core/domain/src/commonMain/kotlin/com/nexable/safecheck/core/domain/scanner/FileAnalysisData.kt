package com.nexable.safecheck.core.domain.scanner

import kotlinx.datetime.Instant

/**
 * Comprehensive file analysis results container.
 */
data class FileAnalysisResults(
    val originalHash: String,
    val normalizedHash: String,
    val hashFormat: HashFormat,
    val hashValidation: HashValidationAnalysis,
    val maliciousHashAnalysis: MaliciousHashAnalysis,
    val fileTypeAnalysis: FileTypeAnalysis,
    val reputationAnalysis: FileReputationAnalysis,
    val metadataAnalysis: FileMetadataAnalysis,
    val virusTotalAnalysis: VirusTotalAnalysis?
)

/**
 * Hash format types supported by the scanner.
 */
enum class HashFormat {
    SHA256,
    SHA1,
    MD5,
    SHA512,
    UNKNOWN
}

/**
 * Hash validation analysis results.
 */
data class HashValidationAnalysis(
    val originalHash: String,
    val isValid: Boolean,
    val format: HashFormat,
    val normalizedHash: String,
    val validationIssues: List<HashValidationIssue> = emptyList()
)

/**
 * Hash validation issues found during analysis.
 */
data class HashValidationIssue(
    val type: HashValidationIssueType,
    val description: String,
    val severity: FileHashSeverity
)

enum class HashValidationIssueType {
    INVALID_LENGTH,
    INVALID_CHARACTERS,
    UNKNOWN_FORMAT,
    CASE_MISMATCH,
    WHITESPACE_ISSUES
}

enum class FileHashSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

/**
 * Malicious hash analysis results.
 */
data class MaliciousHashAnalysis(
    val hash: String,
    val isMalicious: Boolean,
    val threatType: ThreatType = ThreatType.UNKNOWN,
    val malwareFamily: String? = null,
    val confidence: Double = 0.0,
    val threatSources: List<ThreatSource> = emptyList(),
    val firstSeen: Instant? = null,
    val lastSeen: Instant? = null
)

enum class ThreatType {
    MALWARE,
    VIRUS,
    TROJAN,
    WORM,
    RANSOMWARE,
    SPYWARE,
    ADWARE,
    ROOTKIT,
    BACKDOOR,
    BOTNET,
    PHISHING,
    SUSPICIOUS,
    UNKNOWN
}

/**
 * Threat source information.
 */
data class ThreatSource(
    val name: String,
    val verdict: String,
    val confidence: Double,
    val scanDate: Instant? = null,
    val details: Map<String, String> = emptyMap()
)

/**
 * File type analysis results.
 */
data class FileTypeAnalysis(
    val hash: String,
    val detectedFileType: FileType,
    val fileExtension: String? = null,
    val mimeType: String? = null,
    val confidence: Double = 0.0,
    val fileTypeIndicators: List<FileTypeIndicator> = emptyList(),
    val isSuspiciousType: Boolean = false
)

enum class FileType {
    EXECUTABLE_WINDOWS,     // .exe, .dll, .scr, .com, .bat, .cmd
    EXECUTABLE_LINUX,       // ELF binaries
    EXECUTABLE_MACOS,       // Mach-O binaries
    SCRIPT,                 // .ps1, .sh, .py, .js, .vbs
    DOCUMENT,               // .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx
    ARCHIVE,                // .zip, .rar, .7z, .tar, .gz
    IMAGE,                  // .jpg, .png, .gif, .bmp, .svg
    AUDIO,                  // .mp3, .wav, .flac, .ogg
    VIDEO,                  // .mp4, .avi, .mkv, .mov
    TEXT,                   // .txt, .log, .csv
    DATA,                   // Generic data files
    UNKNOWN
}

/**
 * File type indicator used for detection.
 */
data class FileTypeIndicator(
    val type: FileTypeIndicatorType,
    val value: String,
    val confidence: Double
)

enum class FileTypeIndicatorType {
    MAGIC_BYTES,
    FILE_EXTENSION,
    HASH_PATTERN,
    SIZE_PATTERN
}

/**
 * File reputation analysis results.
 */
data class FileReputationAnalysis(
    val hash: String,
    val reputationScore: Int = 50, // 0-100 scale
    val isKnownGood: Boolean = false,
    val isKnownBad: Boolean = false,
    val isSuspicious: Boolean = false,
    val reputationSources: List<ReputationSource> = emptyList(),
    val prevalence: FilePrevalence = FilePrevalence.UNKNOWN,
    val lastChecked: Instant
)

enum class FilePrevalence {
    VERY_COMMON,    // Seen millions of times
    COMMON,         // Seen thousands of times
    UNCOMMON,       // Seen hundreds of times
    RARE,           // Seen tens of times
    VERY_RARE,      // Seen few times
    UNKNOWN
}

/**
 * File metadata analysis results.
 */
data class FileMetadataAnalysis(
    val hash: String,
    val estimatedFileSize: Long? = null,
    val possibleFilenames: List<String> = emptyList(),
    val creationTimeEstimate: Instant? = null,
    val distributionScore: Int = 50, // How widely distributed this file is
    val ageAnalysis: FileAgeAnalysis? = null,
    val anomalyFlags: List<MetadataAnomalyFlag> = emptyList()
)

/**
 * File age analysis results.
 */
data class FileAgeAnalysis(
    val estimatedAge: FileDuration,
    val isVeryNew: Boolean = false,
    val isVeryOld: Boolean = false,
    val ageConfidence: Double = 0.0
)

enum class FileDuration {
    MINUTES,
    HOURS,
    DAYS,
    WEEKS,
    MONTHS,
    YEARS,
    UNKNOWN
}

/**
 * Metadata anomaly flags.
 */
data class MetadataAnomalyFlag(
    val type: AnomalyType,
    val description: String,
    val severity: FileHashSeverity
)

enum class AnomalyType {
    UNUSUAL_SIZE,
    SUSPICIOUS_NAME,
    RAPID_DISTRIBUTION,
    UNUSUAL_CREATION_TIME,
    METADATA_MISMATCH
}

/**
 * VirusTotal analysis results.
 */
data class VirusTotalAnalysis(
    val hash: String,
    val scanId: String? = null,
    val positiveDetections: Int = 0,
    val totalEngines: Int = 0,
    val scanDate: Instant? = null,
    val permalink: String? = null,
    val detectionResults: List<AntivirusDetection> = emptyList(),
    val isAvailable: Boolean = false,
    val errorMessage: String? = null
)

/**
 * Individual antivirus detection result.
 */
data class AntivirusDetection(
    val engine: String,
    val version: String,
    val result: String? = null,
    val isDetected: Boolean = false,
    val updateDate: String? = null
)

/**
 * File hash normalization and validation utilities.
 */
object FileHashUtils {
    
    /**
     * Detects the hash format based on length and characters.
     */
    fun detectHashFormat(hash: String): HashFormat {
        val cleanHash = hash.trim().replace(Regex("[^a-fA-F0-9]"), "")
        
        return when (cleanHash.length) {
            32 -> HashFormat.MD5
            40 -> HashFormat.SHA1
            64 -> HashFormat.SHA256
            128 -> HashFormat.SHA512
            else -> HashFormat.UNKNOWN
        }
    }
    
    /**
     * Validates hash format and characters.
     */
    fun validateHash(hash: String): HashValidationAnalysis {
        val issues = mutableListOf<HashValidationIssue>()
        val trimmedHash = hash.trim()
        val format = detectHashFormat(trimmedHash)
        
        // Check for whitespace issues
        if (hash != trimmedHash) {
            issues.add(HashValidationIssue(
                HashValidationIssueType.WHITESPACE_ISSUES,
                "Hash contains leading or trailing whitespace",
                FileHashSeverity.LOW
            ))
        }
        
        // Check for invalid characters
        if (!trimmedHash.matches(Regex("[a-fA-F0-9]+"))) {
            issues.add(HashValidationIssue(
                HashValidationIssueType.INVALID_CHARACTERS,
                "Hash contains invalid characters (only hexadecimal allowed)",
                FileHashSeverity.HIGH
            ))
        }
        
        // Check length for known formats
        if (format == HashFormat.UNKNOWN && trimmedHash.isNotEmpty()) {
            issues.add(HashValidationIssue(
                HashValidationIssueType.UNKNOWN_FORMAT,
                "Hash length does not match any known format",
                FileHashSeverity.MEDIUM
            ))
        }
        
        val normalizedHash = trimmedHash.lowercase()
        val isValid = issues.none { it.severity in listOf(FileHashSeverity.HIGH, FileHashSeverity.CRITICAL) }
        
        return HashValidationAnalysis(
            originalHash = hash,
            isValid = isValid,
            format = format,
            normalizedHash = normalizedHash,
            validationIssues = issues
        )
    }
    
    /**
     * Normalizes hash to lowercase without spaces.
     */
    fun normalizeHash(hash: String): String {
        return hash.trim().lowercase()
    }
}
