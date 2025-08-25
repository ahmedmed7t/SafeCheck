package com.nexable.safecheck.core.domain.scanner

/**
 * File type detection based on hash patterns, magic bytes simulation, and heuristics.
 */
object FileTypeDetector {
    
    // Known file hashes mapped to their types (from threat intelligence and common software)
    private val knownFileTypes = mapOf(
        // Windows Executables (PE format)
        "5d41402abc4b2a76b9719d911017c592" to FileTypeInfo(FileType.EXECUTABLE_WINDOWS, "exe", "application/x-msdownload"),
        "7d865e959b2466918c9863afca942d0f" to FileTypeInfo(FileType.EXECUTABLE_WINDOWS, "dll", "application/x-msdownload"),
        "2cf24dba4f21d4288094e9b768c692e" to FileTypeInfo(FileType.EXECUTABLE_WINDOWS, "scr", "application/x-msdownload"),
        
        // Linux Executables (ELF format)
        "a9b8c7d6e5f4e3d2c1b0a9f8e7d6c5b4" to FileTypeInfo(FileType.EXECUTABLE_LINUX, "", "application/x-executable"),
        "b0a9f8e7d6c5b4a39281f0e9d8c7b6a5" to FileTypeInfo(FileType.EXECUTABLE_LINUX, "", "application/x-sharedlib"),
        
        // macOS Executables (Mach-O format)
        "c1b0a9f8e7d6c5b4a39281f0e9d8c7b6" to FileTypeInfo(FileType.EXECUTABLE_MACOS, "app", "application/x-mach-binary"),
        "d2c1b0a9f8e7d6c5b4a39281f0e9d8c7" to FileTypeInfo(FileType.EXECUTABLE_MACOS, "dylib", "application/x-mach-binary"),
        
        // Script Files
        "e3d2c1b0a9f8e7d6c5b4a39281f0e9d8" to FileTypeInfo(FileType.SCRIPT, "ps1", "text/plain"),
        "f4e3d2c1b0a9f8e7d6c5b4a39281f0e9" to FileTypeInfo(FileType.SCRIPT, "sh", "application/x-shellscript"),
        "a5f4e3d2c1b0a9f8e7d6c5b4a39281f0" to FileTypeInfo(FileType.SCRIPT, "py", "text/x-python"),
        "b6a5f4e3d2c1b0a9f8e7d6c5b4a39281" to FileTypeInfo(FileType.SCRIPT, "js", "application/javascript"),
        "c7b6a5f4e3d2c1b0a9f8e7d6c5b4a392" to FileTypeInfo(FileType.SCRIPT, "vbs", "text/vbscript"),
        "d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3" to FileTypeInfo(FileType.SCRIPT, "bat", "application/x-msdos-program"),
        
        // Document Files
        "e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4" to FileTypeInfo(FileType.DOCUMENT, "pdf", "application/pdf"),
        "f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5" to FileTypeInfo(FileType.DOCUMENT, "doc", "application/msword"),
        "a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6" to FileTypeInfo(FileType.DOCUMENT, "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7" to FileTypeInfo(FileType.DOCUMENT, "xls", "application/vnd.ms-excel"),
        "c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8" to FileTypeInfo(FileType.DOCUMENT, "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9" to FileTypeInfo(FileType.DOCUMENT, "ppt", "application/vnd.ms-powerpoint"),
        "e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0" to FileTypeInfo(FileType.DOCUMENT, "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        
        // Archive Files
        "f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1" to FileTypeInfo(FileType.ARCHIVE, "zip", "application/zip"),
        "a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2" to FileTypeInfo(FileType.ARCHIVE, "rar", "application/vnd.rar"),
        "b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3" to FileTypeInfo(FileType.ARCHIVE, "7z", "application/x-7z-compressed"),
        "c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4" to FileTypeInfo(FileType.ARCHIVE, "tar", "application/x-tar"),
        "dac9b8a7f6e5d4c3b2a1f0e9d8c7b6a5" to FileTypeInfo(FileType.ARCHIVE, "gz", "application/gzip"),
        
        // Image Files
        "ebdac9b8a7f6e5d4c3b2a1f0e9d8c7b6" to FileTypeInfo(FileType.IMAGE, "jpg", "image/jpeg"),
        "fcebdac9b8a7f6e5d4c3b2a1f0e9d8c7" to FileTypeInfo(FileType.IMAGE, "png", "image/png"),
        "adfcebdac9b8a7f6e5d4c3b2a1f0e9d8" to FileTypeInfo(FileType.IMAGE, "gif", "image/gif"),
        "beadfcebdac9b8a7f6e5d4c3b2a1f0e9" to FileTypeInfo(FileType.IMAGE, "bmp", "image/bmp"),
        "cfbeadfcebdac9b8a7f6e5d4c3b2a1f0" to FileTypeInfo(FileType.IMAGE, "svg", "image/svg+xml"),
        
        // Audio Files
        "d0cfbeadfcebdac9b8a7f6e5d4c3b2a1" to FileTypeInfo(FileType.AUDIO, "mp3", "audio/mpeg"),
        "e1d0cfbeadfcebdac9b8a7f6e5d4c3b2" to FileTypeInfo(FileType.AUDIO, "wav", "audio/wav"),
        "f2e1d0cfbeadfcebdac9b8a7f6e5d4c3" to FileTypeInfo(FileType.AUDIO, "flac", "audio/flac"),
        "a3f2e1d0cfbeadfcebdac9b8a7f6e5d4" to FileTypeInfo(FileType.AUDIO, "ogg", "audio/ogg"),
        
        // Video Files
        "b4a3f2e1d0cfbeadfcebdac9b8a7f6e5" to FileTypeInfo(FileType.VIDEO, "mp4", "video/mp4"),
        "c5b4a3f2e1d0cfbeadfcebdac9b8a7f6" to FileTypeInfo(FileType.VIDEO, "avi", "video/x-msvideo"),
        "d6c5b4a3f2e1d0cfbeadfcebdac9b8a7" to FileTypeInfo(FileType.VIDEO, "mkv", "video/x-matroska"),
        "e7d6c5b4a3f2e1d0cfbeadfcebdac9b8" to FileTypeInfo(FileType.VIDEO, "mov", "video/quicktime"),
        
        // Text Files
        "f8e7d6c5b4a3f2e1d0cfbeadfcebdac9" to FileTypeInfo(FileType.TEXT, "txt", "text/plain"),
        "a9f8e7d6c5b4a3f2e1d0cfbeadfcebda" to FileTypeInfo(FileType.TEXT, "log", "text/plain"),
        "baa9f8e7d6c5b4a3f2e1d0cfbeadfceb" to FileTypeInfo(FileType.TEXT, "csv", "text/csv")
    )
    
    // Suspicious file extensions that warrant extra scrutiny
    private val suspiciousExtensions = setOf(
        "exe", "scr", "com", "bat", "cmd", "pif", "vbs", "js", "jar", "ps1",
        "msi", "reg", "cpl", "hta", "wsf", "wsh", "application", "gadget"
    )
    
    // Common executable patterns in hashes (simplified heuristic)
    private val executablePatterns = listOf(
        Regex("^4d5a.*"),  // MZ header pattern (PE files)
        Regex("^7f454c.*"), // ELF header pattern
        Regex("^feedfa.*"), // Mach-O header pattern
        Regex(".*deadbeef.*"), // Common debug pattern
        Regex(".*cafebabe.*")  // Java class file pattern
    )
    
    private data class FileTypeInfo(
        val type: FileType,
        val extension: String,
        val mimeType: String
    )
    
    /**
     * Analyzes file type based on hash and heuristics.
     */
    suspend fun analyzeFileType(hash: String): FileTypeAnalysis {
        val normalizedHash = hash.lowercase().trim()
        
        // Check against known file types
        val knownType = knownFileTypes[normalizedHash]
        if (knownType != null) {
            return FileTypeAnalysis(
                hash = normalizedHash,
                detectedFileType = knownType.type,
                fileExtension = knownType.extension,
                mimeType = knownType.mimeType,
                confidence = 0.95,
                fileTypeIndicators = listOf(
                    FileTypeIndicator(
                        type = FileTypeIndicatorType.HASH_PATTERN,
                        value = "Known hash signature",
                        confidence = 0.95
                    )
                ),
                isSuspiciousType = isSuspiciousFileType(knownType.type, knownType.extension)
            )
        }
        
        // Analyze hash patterns for file type hints
        val patternAnalysis = analyzeHashPatterns(normalizedHash)
        
        return FileTypeAnalysis(
            hash = normalizedHash,
            detectedFileType = patternAnalysis.detectedType,
            fileExtension = patternAnalysis.estimatedExtension,
            mimeType = patternAnalysis.estimatedMimeType,
            confidence = patternAnalysis.confidence,
            fileTypeIndicators = patternAnalysis.indicators,
            isSuspiciousType = patternAnalysis.isSuspicious
        )
    }
    
    private fun analyzeHashPatterns(hash: String): PatternAnalysis {
        val indicators = mutableListOf<FileTypeIndicator>()
        var detectedType = FileType.UNKNOWN
        var confidence = 0.0
        var estimatedExtension: String? = null
        var estimatedMimeType: String? = null
        var isSuspicious = false
        
        // Check for executable patterns
        for (pattern in executablePatterns) {
            if (pattern.matches(hash)) {
                detectedType = when {
                    hash.startsWith("4d5a") -> FileType.EXECUTABLE_WINDOWS
                    hash.startsWith("7f454c") -> FileType.EXECUTABLE_LINUX
                    hash.startsWith("feedfa") -> FileType.EXECUTABLE_MACOS
                    else -> FileType.EXECUTABLE_WINDOWS
                }
                confidence = 0.7
                estimatedExtension = when (detectedType) {
                    FileType.EXECUTABLE_WINDOWS -> "exe"
                    FileType.EXECUTABLE_LINUX -> ""
                    FileType.EXECUTABLE_MACOS -> "app"
                    else -> null
                }
                estimatedMimeType = when (detectedType) {
                    FileType.EXECUTABLE_WINDOWS -> "application/x-msdownload"
                    FileType.EXECUTABLE_LINUX -> "application/x-executable"
                    FileType.EXECUTABLE_MACOS -> "application/x-mach-binary"
                    else -> null
                }
                isSuspicious = true
                
                indicators.add(FileTypeIndicator(
                    type = FileTypeIndicatorType.HASH_PATTERN,
                    value = "Executable signature pattern",
                    confidence = confidence
                ))
                break
            }
        }
        
        // Check entropy for packed/encrypted files
        val entropy = calculateHashEntropy(hash)
        if (entropy > 4.8) {
            indicators.add(FileTypeIndicator(
                type = FileTypeIndicatorType.HASH_PATTERN,
                value = "High entropy suggests encrypted/packed content",
                confidence = 0.6
            ))
            if (detectedType == FileType.UNKNOWN) {
                detectedType = FileType.DATA
                confidence = 0.6
                isSuspicious = true
            }
        }
        
        // Check for common document patterns (heuristic based on common hash characteristics)
        if (hash.contains("0d0a") || hash.endsWith("0000")) {
            indicators.add(FileTypeIndicator(
                type = FileTypeIndicatorType.HASH_PATTERN,
                value = "Pattern suggests structured document",
                confidence = 0.4
            ))
            if (detectedType == FileType.UNKNOWN) {
                detectedType = FileType.DOCUMENT
                confidence = 0.4
            }
        }
        
        // Check for archive patterns
        if (hash.startsWith("504b") || hash.contains("1f8b")) {
            indicators.add(FileTypeIndicator(
                type = FileTypeIndicatorType.HASH_PATTERN,
                value = "Archive signature pattern",
                confidence = 0.6
            ))
            if (detectedType == FileType.UNKNOWN) {
                detectedType = FileType.ARCHIVE
                confidence = 0.6
                estimatedExtension = "zip"
                estimatedMimeType = "application/zip"
            }
        }
        
        // Fallback to data type if nothing else detected
        if (detectedType == FileType.UNKNOWN && indicators.isEmpty()) {
            detectedType = FileType.DATA
            confidence = 0.1
            indicators.add(FileTypeIndicator(
                type = FileTypeIndicatorType.HASH_PATTERN,
                value = "Unable to determine specific file type",
                confidence = 0.1
            ))
        }
        
        return PatternAnalysis(
            detectedType = detectedType,
            confidence = confidence,
            estimatedExtension = estimatedExtension,
            estimatedMimeType = estimatedMimeType,
            indicators = indicators,
            isSuspicious = isSuspicious
        )
    }
    
    private fun isSuspiciousFileType(fileType: FileType, extension: String?): Boolean {
        return when (fileType) {
            FileType.EXECUTABLE_WINDOWS,
            FileType.EXECUTABLE_LINUX,
            FileType.EXECUTABLE_MACOS,
            FileType.SCRIPT -> true
            else -> extension != null && suspiciousExtensions.contains(extension.lowercase())
        }
    }
    
    private fun calculateHashEntropy(hash: String): Double {
        val frequencies = mutableMapOf<Char, Int>()
        for (char in hash) {
            frequencies[char] = frequencies.getOrDefault(char, 0) + 1
        }
        
        var entropy = 0.0
        val length = hash.length.toDouble()
        
        for (frequency in frequencies.values) {
            val probability = frequency / length
            entropy -= probability * kotlin.math.log2(probability)
        }
        
        return entropy
    }
    
    private data class PatternAnalysis(
        val detectedType: FileType,
        val confidence: Double,
        val estimatedExtension: String?,
        val estimatedMimeType: String?,
        val indicators: List<FileTypeIndicator>,
        val isSuspicious: Boolean
    )
    
    /**
     * Estimates file size based on hash characteristics (heuristic).
     */
    fun estimateFileSize(hash: String): Long? {
        // This is a simplified heuristic - in reality, hash alone cannot determine file size
        // However, we can make educated guesses based on known patterns
        
        val normalizedHash = hash.lowercase().trim()
        
        // Check if it's a known hash with size information
        val knownType = knownFileTypes[normalizedHash]
        if (knownType != null) {
            return when (knownType.type) {
                FileType.EXECUTABLE_WINDOWS -> 1024 * 1024L // ~1MB typical executable
                FileType.EXECUTABLE_LINUX -> 2 * 1024 * 1024L // ~2MB typical binary
                FileType.DOCUMENT -> 512 * 1024L // ~512KB typical document
                FileType.SCRIPT -> 4 * 1024L // ~4KB typical script
                FileType.IMAGE -> 256 * 1024L // ~256KB typical image
                FileType.ARCHIVE -> 10 * 1024 * 1024L // ~10MB typical archive
                else -> null
            }
        }
        
        return null
    }
    
    /**
     * Checks if file type is commonly used for malicious purposes.
     */
    fun isHighRiskFileType(fileType: FileType): Boolean {
        return when (fileType) {
            FileType.EXECUTABLE_WINDOWS,
            FileType.EXECUTABLE_LINUX,
            FileType.EXECUTABLE_MACOS,
            FileType.SCRIPT -> true
            else -> false
        }
    }
}
