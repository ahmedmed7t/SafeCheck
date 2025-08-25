package com.nexable.safecheck.core.domain.scanner

import com.nexable.safecheck.core.domain.model.Result

/**
 * Email syntax validator following RFC 5322 standards.
 */
object EmailValidator {
    
    private const val MAX_EMAIL_LENGTH = 320
    private const val MAX_LOCAL_LENGTH = 64
    private const val MAX_DOMAIN_LENGTH = 253
    
    /**
     * Validates email syntax according to RFC 5322.
     */
    fun validate(email: String): EmailSyntaxAnalysis {
        val issues = mutableListOf<EmailSyntaxIssue>()
        val normalizedEmail = email.trim().lowercase()
        
        // Basic structure validation
        if (email.length > MAX_EMAIL_LENGTH) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.TOO_LONG,
                "Email exceeds maximum length of $MAX_EMAIL_LENGTH characters",
                EmailSeverity.HIGH
            ))
        }
        
        val atIndex = email.indexOf('@')
        val lastAtIndex = email.lastIndexOf('@')
        
        if (atIndex == -1) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.MISSING_AT_SYMBOL,
                "Email must contain an @ symbol",
                EmailSeverity.CRITICAL
            ))
            return createFailureResult(email, normalizedEmail, issues)
        }
        
        if (atIndex != lastAtIndex) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.MULTIPLE_AT_SYMBOLS,
                "Email contains multiple @ symbols",
                EmailSeverity.CRITICAL
            ))
            return createFailureResult(email, normalizedEmail, issues)
        }
        
        val localPart = email.substring(0, atIndex)
        val domain = email.substring(atIndex + 1)
        
        // Validate local part
        val localPartValid = validateLocalPart(localPart, issues)
        
        // Validate domain part
        val domainValid = validateDomainPart(domain, issues)
        
        val isValid = issues.none { it.severity == EmailSeverity.CRITICAL }
        val rfc5322Compliant = isValid && issues.isEmpty()
        
        return EmailSyntaxAnalysis(
            email = email,
            isValid = isValid,
            rfc5322Compliant = rfc5322Compliant,
            hasValidLocalPart = localPartValid,
            hasValidDomain = domainValid,
            syntaxIssues = issues,
            normalizedForm = normalizedEmail
        )
    }
    
    private fun validateLocalPart(localPart: String, issues: MutableList<EmailSyntaxIssue>): Boolean {
        if (localPart.isEmpty()) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_LOCAL_PART,
                "Local part cannot be empty",
                EmailSeverity.CRITICAL
            ))
            return false
        }
        
        if (localPart.length > MAX_LOCAL_LENGTH) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_LOCAL_PART,
                "Local part exceeds maximum length of $MAX_LOCAL_LENGTH characters",
                EmailSeverity.HIGH
            ))
        }
        
        // Check for quoted string
        if (localPart.startsWith("\"") && localPart.endsWith("\"")) {
            return validateQuotedLocalPart(localPart, issues)
        }
        
        // Validate unquoted local part
        return validateUnquotedLocalPart(localPart, issues)
    }
    
    private fun validateUnquotedLocalPart(localPart: String, issues: MutableList<EmailSyntaxIssue>): Boolean {
        var isValid = true
        
        // Check for invalid characters
        val invalidChars = localPart.filter { char ->
            !char.isLetterOrDigit() && char !in "!#$%&'*+-/=?^_`{|}~."
        }
        
        if (invalidChars.isNotEmpty()) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_CHARACTERS,
                "Local part contains invalid characters: ${invalidChars.toSet()}",
                EmailSeverity.HIGH
            ))
            isValid = false
        }
        
        // Check for consecutive dots
        if (localPart.contains("..")) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_LOCAL_PART,
                "Local part cannot contain consecutive dots",
                EmailSeverity.HIGH
            ))
            isValid = false
        }
        
        // Check for leading or trailing dots
        if (localPart.startsWith(".") || localPart.endsWith(".")) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_LOCAL_PART,
                "Local part cannot start or end with a dot",
                EmailSeverity.HIGH
            ))
            isValid = false
        }
        
        return isValid
    }
    
    private fun validateQuotedLocalPart(localPart: String, issues: MutableList<EmailSyntaxIssue>): Boolean {
        if (localPart.length < 3) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.QUOTED_STRING_ISSUES,
                "Quoted string must contain at least one character",
                EmailSeverity.HIGH
            ))
            return false
        }
        
        val content = localPart.substring(1, localPart.length - 1)
        
        // Check for unescaped quotes or backslashes
        var i = 0
        while (i < content.length) {
            val char = content[i]
            if (char == '"' || char == '\\') {
                if (i == 0 || content[i - 1] != '\\') {
                    issues.add(EmailSyntaxIssue(
                        EmailSyntaxIssueType.QUOTED_STRING_ISSUES,
                        "Unescaped quote or backslash in quoted string",
                        EmailSeverity.HIGH
                    ))
                    return false
                }
            }
            i++
        }
        
        return true
    }
    
    private fun validateDomainPart(domain: String, issues: MutableList<EmailSyntaxIssue>): Boolean {
        if (domain.isEmpty()) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_DOMAIN,
                "Domain part cannot be empty",
                EmailSeverity.CRITICAL
            ))
            return false
        }
        
        if (domain.length > MAX_DOMAIN_LENGTH) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_DOMAIN,
                "Domain part exceeds maximum length of $MAX_DOMAIN_LENGTH characters",
                EmailSeverity.HIGH
            ))
        }
        
        // Check for IP address literal
        if (domain.startsWith("[") && domain.endsWith("]")) {
            return validateIpLiteral(domain, issues)
        }
        
        // Validate domain name
        return validateDomainName(domain, issues)
    }
    
    private fun validateIpLiteral(domain: String, issues: MutableList<EmailSyntaxIssue>): Boolean {
        val ipAddress = domain.substring(1, domain.length - 1)
        
        // Basic IPv4 validation
        if (ipAddress.matches(Regex("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"))) {
            val parts = ipAddress.split(".")
            for (part in parts) {
                val num = part.toIntOrNull()
                if (num == null || num > 255) {
                    issues.add(EmailSyntaxIssue(
                        EmailSyntaxIssueType.INVALID_DOMAIN,
                        "Invalid IPv4 address in domain literal",
                        EmailSeverity.HIGH
                    ))
                    return false
                }
            }
            return true
        }
        
        // IPv6 or other address literal - simplified validation
        if (ipAddress.contains(":")) {
            // Basic IPv6 validation
            return true
        }
        
        issues.add(EmailSyntaxIssue(
            EmailSyntaxIssueType.INVALID_DOMAIN,
            "Invalid address literal format",
            EmailSeverity.HIGH
        ))
        return false
    }
    
    private fun validateDomainName(domain: String, issues: MutableList<EmailSyntaxIssue>): Boolean {
        var isValid = true
        
        // Check for consecutive dots
        if (domain.contains("..")) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_DOMAIN,
                "Domain cannot contain consecutive dots",
                EmailSeverity.HIGH
            ))
            isValid = false
        }
        
        // Check for leading or trailing dots
        if (domain.startsWith(".") || domain.endsWith(".")) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_DOMAIN,
                "Domain cannot start or end with a dot",
                EmailSeverity.HIGH
            ))
            isValid = false
        }
        
        // Validate each label
        val labels = domain.split(".")
        for (label in labels) {
            if (!validateDomainLabel(label)) {
                issues.add(EmailSyntaxIssue(
                    EmailSyntaxIssueType.INVALID_DOMAIN,
                    "Invalid domain label: '$label'",
                    EmailSeverity.HIGH
                ))
                isValid = false
            }
        }
        
        // Must have at least one dot (TLD requirement)
        if (!domain.contains(".")) {
            issues.add(EmailSyntaxIssue(
                EmailSyntaxIssueType.INVALID_DOMAIN,
                "Domain must contain at least one dot",
                EmailSeverity.MEDIUM
            ))
        }
        
        return isValid
    }
    
    private fun validateDomainLabel(label: String): Boolean {
        if (label.isEmpty() || label.length > 63) {
            return false
        }
        
        // Must start and end with alphanumeric
        if (!label.first().isLetterOrDigit() || !label.last().isLetterOrDigit()) {
            return false
        }
        
        // Can contain letters, digits, and hyphens
        return label.all { it.isLetterOrDigit() || it == '-' }
    }
    
    private fun createFailureResult(
        email: String, 
        normalizedEmail: String, 
        issues: List<EmailSyntaxIssue>
    ): EmailSyntaxAnalysis {
        return EmailSyntaxAnalysis(
            email = email,
            isValid = false,
            rfc5322Compliant = false,
            hasValidLocalPart = false,
            hasValidDomain = false,
            syntaxIssues = issues,
            normalizedForm = normalizedEmail
        )
    }
}

/**
 * Email parsing utilities.
 */
object EmailParser {
    
    /**
     * Extracts the local part from an email address.
     */
    fun extractLocalPart(email: String): String {
        val atIndex = email.indexOf('@')
        return if (atIndex != -1) email.substring(0, atIndex) else ""
    }
    
    /**
     * Extracts the domain part from an email address.
     */
    fun extractDomain(email: String): String {
        val atIndex = email.indexOf('@')
        return if (atIndex != -1 && atIndex < email.length - 1) {
            email.substring(atIndex + 1)
        } else ""
    }
    
    /**
     * Normalizes an email address to lowercase.
     */
    fun normalize(email: String): String {
        return email.trim().lowercase()
    }
    
    /**
     * Checks if email has a valid basic structure.
     */
    fun hasValidStructure(email: String): Boolean {
        val atIndex = email.indexOf('@')
        return atIndex > 0 && atIndex < email.length - 1 && email.indexOf('@', atIndex + 1) == -1
    }
}
