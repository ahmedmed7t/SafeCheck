package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Reason

/**
 * Calculates security scores for file hashes based on comprehensive analysis results.
 */
object FileScoreCalculator {
    
    /**
     * Calculates the overall security score based on all file analysis results.
     */
    fun calculateScore(analysis: FileAnalysisResults): Pair<Int, List<Reason>> {
        val reasons = mutableListOf<Reason>()
        var score = 100 // Start with perfect score
        
        // Hash Validation Analysis (5% weight)
        score += analyzeHashValidation(analysis.hashValidation, reasons)
        
        // Malicious Hash Analysis (35% weight)
        score += analyzeMaliciousHash(analysis.maliciousHashAnalysis, reasons)
        
        // File Type Analysis (15% weight)
        score += analyzeFileType(analysis.fileTypeAnalysis, reasons)
        
        // Reputation Analysis (25% weight)
        score += analyzeReputation(analysis.reputationAnalysis, reasons)
        
        // Metadata Analysis (10% weight)
        score += analyzeMetadata(analysis.metadataAnalysis, reasons)
        
        // VirusTotal Analysis (10% weight, if available)
        analysis.virusTotalAnalysis?.let { vtAnalysis ->
            score += analyzeVirusTotal(vtAnalysis, reasons)
        }
        
        // Ensure score stays within bounds
        score = score.coerceIn(0, 100)
        
        return Pair(score, reasons)
    }
    
    /**
     * Analyzes hash validation and returns score delta.
     */
    private fun analyzeHashValidation(hashValidation: HashValidationAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (!hashValidation.isValid) {
            reasons.add(Reason("INVALID_HASH", "Hash format is invalid", -10))
            scoreDelta -= 10
        } else {
            reasons.add(Reason("VALID_HASH", "Hash format is valid", 0))
        }
        
        // Analyze specific validation issues
        for (issue in hashValidation.validationIssues) {
            val severity = when (issue.severity) {
                FileHashSeverity.CRITICAL -> -8
                FileHashSeverity.HIGH -> -5
                FileHashSeverity.MEDIUM -> -3
                FileHashSeverity.LOW -> -1
            }
            reasons.add(Reason("HASH_VALIDATION_ISSUE", issue.description, severity))
            scoreDelta += severity
        }
        
        // Bonus for strong hash formats
        when (hashValidation.format) {
            HashFormat.SHA256 -> {
                reasons.add(Reason("STRONG_HASH_FORMAT", "Uses SHA-256 (recommended)", 2))
                scoreDelta += 2
            }
            HashFormat.SHA512 -> {
                reasons.add(Reason("VERY_STRONG_HASH_FORMAT", "Uses SHA-512 (very strong)", 3))
                scoreDelta += 3
            }
            HashFormat.SHA1 -> {
                reasons.add(Reason("WEAK_HASH_FORMAT", "Uses SHA-1 (deprecated)", -2))
                scoreDelta -= 2
            }
            HashFormat.MD5 -> {
                reasons.add(Reason("VERY_WEAK_HASH_FORMAT", "Uses MD5 (very weak)", -3))
                scoreDelta -= 3
            }
            HashFormat.UNKNOWN -> {
                reasons.add(Reason("UNKNOWN_HASH_FORMAT", "Unknown hash format", -2))
                scoreDelta -= 2
            }
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes malicious hash indicators and returns score delta.
     */
    private fun analyzeMaliciousHash(maliciousAnalysis: MaliciousHashAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (maliciousAnalysis.isMalicious) {
            val severity = when (maliciousAnalysis.threatType) {
                ThreatType.RANSOMWARE -> -60
                ThreatType.TROJAN -> -50
                ThreatType.VIRUS -> -45
                ThreatType.WORM -> -40
                ThreatType.ROOTKIT -> -55
                ThreatType.BACKDOOR -> -50
                ThreatType.SPYWARE -> -35
                ThreatType.BOTNET -> -40
                ThreatType.PHISHING -> -30
                ThreatType.ADWARE -> -20
                ThreatType.SUSPICIOUS -> -25
                ThreatType.MALWARE -> -45
                ThreatType.UNKNOWN -> -30
            }
            
            val familyInfo = if (!maliciousAnalysis.malwareFamily.isNullOrEmpty()) {
                " (${maliciousAnalysis.malwareFamily})"
            } else ""
            
            reasons.add(Reason(
                "KNOWN_MALICIOUS", 
                "File is known ${maliciousAnalysis.threatType.name.lowercase()}$familyInfo", 
                severity
            ))
            scoreDelta += severity
            
        } else {
            // Check threat sources for positive indicators
            for (source in maliciousAnalysis.threatSources) {
                when (source.verdict) {
                    "CLEAN" -> {
                        reasons.add(Reason("KNOWN_CLEAN", "File verified as clean by ${source.name}", 5))
                        scoreDelta += 5
                    }
                    "SUSPICIOUS" -> {
                        reasons.add(Reason("SUSPICIOUS_PATTERNS", "File has suspicious patterns", -10))
                        scoreDelta -= 10
                    }
                }
            }
            
            if (maliciousAnalysis.threatSources.isEmpty()) {
                reasons.add(Reason("UNKNOWN_FILE", "File not found in threat databases", 0))
            }
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes file type and returns score delta.
     */
    private fun analyzeFileType(fileTypeAnalysis: FileTypeAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        // Assess risk based on file type
        when (fileTypeAnalysis.detectedFileType) {
            FileType.EXECUTABLE_WINDOWS,
            FileType.EXECUTABLE_LINUX,
            FileType.EXECUTABLE_MACOS -> {
                reasons.add(Reason("EXECUTABLE_FILE", "File is an executable (inherently risky)", -15))
                scoreDelta -= 15
            }
            FileType.SCRIPT -> {
                reasons.add(Reason("SCRIPT_FILE", "File is a script (potentially dangerous)", -20))
                scoreDelta -= 20
            }
            FileType.DOCUMENT -> {
                reasons.add(Reason("DOCUMENT_FILE", "File is a document (can contain macros)", -5))
                scoreDelta -= 5
            }
            FileType.ARCHIVE -> {
                reasons.add(Reason("ARCHIVE_FILE", "File is an archive (can hide malware)", -8))
                scoreDelta -= 8
            }
            FileType.IMAGE,
            FileType.AUDIO,
            FileType.VIDEO,
            FileType.TEXT -> {
                reasons.add(Reason("SAFE_FILE_TYPE", "File type is generally safe", 5))
                scoreDelta += 5
            }
            FileType.DATA -> {
                reasons.add(Reason("DATA_FILE", "Generic data file", 0))
            }
            FileType.UNKNOWN -> {
                reasons.add(Reason("UNKNOWN_FILE_TYPE", "Unable to determine file type", -3))
                scoreDelta -= 3
            }
        }
        
        // Check if file type is flagged as suspicious
        if (fileTypeAnalysis.isSuspiciousType) {
            reasons.add(Reason("SUSPICIOUS_FILE_TYPE", "File type commonly used for malicious purposes", -10))
            scoreDelta -= 10
        }
        
        // Assess confidence in file type detection
        when {
            fileTypeAnalysis.confidence >= 0.9 -> {
                reasons.add(Reason("HIGH_CONFIDENCE_TYPE", "File type detected with high confidence", 2))
                scoreDelta += 2
            }
            fileTypeAnalysis.confidence <= 0.3 -> {
                reasons.add(Reason("LOW_CONFIDENCE_TYPE", "File type detection has low confidence", -2))
                scoreDelta -= 2
            }
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes reputation and returns score delta.
     */
    private fun analyzeReputation(reputationAnalysis: FileReputationAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (reputationAnalysis.isKnownGood) {
            reasons.add(Reason("KNOWN_GOOD_FILE", "File has good reputation", 15))
            scoreDelta += 15
        } else if (reputationAnalysis.isKnownBad) {
            reasons.add(Reason("KNOWN_BAD_FILE", "File has bad reputation", -25))
            scoreDelta -= 25
        } else if (reputationAnalysis.isSuspicious) {
            reasons.add(Reason("SUSPICIOUS_REPUTATION", "File has suspicious reputation", -15))
            scoreDelta -= 15
        }
        
        // Factor in overall reputation score
        when {
            reputationAnalysis.reputationScore >= 80 -> {
                reasons.add(Reason("HIGH_REPUTATION", "File has high reputation score", 10))
                scoreDelta += 10
            }
            reputationAnalysis.reputationScore <= 30 -> {
                reasons.add(Reason("LOW_REPUTATION", "File has low reputation score", -10))
                scoreDelta -= 10
            }
        }
        
        // Assess prevalence
        when (reputationAnalysis.prevalence) {
            FilePrevalence.VERY_COMMON -> {
                reasons.add(Reason("VERY_COMMON_FILE", "File is very commonly seen", 8))
                scoreDelta += 8
            }
            FilePrevalence.COMMON -> {
                reasons.add(Reason("COMMON_FILE", "File is commonly seen", 5))
                scoreDelta += 5
            }
            FilePrevalence.VERY_RARE -> {
                reasons.add(Reason("VERY_RARE_FILE", "File is very rarely seen", -8))
                scoreDelta -= 8
            }
            FilePrevalence.RARE -> {
                reasons.add(Reason("RARE_FILE", "File is rarely seen", -5))
                scoreDelta -= 5
            }
            else -> {
                // Neutral for UNCOMMON and UNKNOWN
            }
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes metadata and returns score delta.
     */
    private fun analyzeMetadata(metadataAnalysis: FileMetadataAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        // Analyze distribution score
        when {
            metadataAnalysis.distributionScore >= 80 -> {
                reasons.add(Reason("WIDELY_DISTRIBUTED", "File is widely distributed", 3))
                scoreDelta += 3
            }
            metadataAnalysis.distributionScore <= 20 -> {
                reasons.add(Reason("LIMITED_DISTRIBUTION", "File has limited distribution", -3))
                scoreDelta -= 3
            }
        }
        
        // Analyze age
        metadataAnalysis.ageAnalysis?.let { ageAnalysis ->
            if (ageAnalysis.isVeryNew) {
                reasons.add(Reason("VERY_NEW_FILE", "File appears to be very new", -5))
                scoreDelta -= 5
            } else if (ageAnalysis.isVeryOld) {
                reasons.add(Reason("ESTABLISHED_FILE", "File appears to be well-established", 3))
                scoreDelta += 3
            }
        }
        
        // Analyze anomaly flags
        for (anomaly in metadataAnalysis.anomalyFlags) {
            val severity = when (anomaly.severity) {
                FileHashSeverity.CRITICAL -> -8
                FileHashSeverity.HIGH -> -5
                FileHashSeverity.MEDIUM -> -3
                FileHashSeverity.LOW -> -1
            }
            reasons.add(Reason("METADATA_ANOMALY", anomaly.description, severity))
            scoreDelta += severity
        }
        
        return scoreDelta
    }
    
    /**
     * Analyzes VirusTotal results and returns score delta.
     */
    private fun analyzeVirusTotal(vtAnalysis: VirusTotalAnalysis, reasons: MutableList<Reason>): Int {
        var scoreDelta = 0
        
        if (!vtAnalysis.isAvailable) {
            reasons.add(Reason("VT_UNAVAILABLE", "VirusTotal analysis unavailable", 0))
            return 0
        }
        
        if (vtAnalysis.totalEngines == 0) {
            reasons.add(Reason("VT_NO_ENGINES", "No VirusTotal engines responded", 0))
            return 0
        }
        
        val detectionRatio = vtAnalysis.positiveDetections.toDouble() / vtAnalysis.totalEngines
        
        when {
            detectionRatio >= 0.5 -> {
                reasons.add(Reason("VT_HIGH_DETECTION", 
                    "${vtAnalysis.positiveDetections}/${vtAnalysis.totalEngines} engines detect malware", -30))
                scoreDelta -= 30
            }
            detectionRatio >= 0.2 -> {
                reasons.add(Reason("VT_MEDIUM_DETECTION", 
                    "${vtAnalysis.positiveDetections}/${vtAnalysis.totalEngines} engines detect threats", -20))
                scoreDelta -= 20
            }
            detectionRatio >= 0.05 -> {
                reasons.add(Reason("VT_LOW_DETECTION", 
                    "${vtAnalysis.positiveDetections}/${vtAnalysis.totalEngines} engines detect suspicious activity", -10))
                scoreDelta -= 10
            }
            vtAnalysis.positiveDetections > 0 -> {
                reasons.add(Reason("VT_MINIMAL_DETECTION", 
                    "Few engines (${vtAnalysis.positiveDetections}) detect potential issues", -5))
                scoreDelta -= 5
            }
            else -> {
                reasons.add(Reason("VT_CLEAN", 
                    "No VirusTotal engines detect threats (${vtAnalysis.totalEngines} engines)", 10))
                scoreDelta += 10
            }
        }
        
        return scoreDelta
    }
}
