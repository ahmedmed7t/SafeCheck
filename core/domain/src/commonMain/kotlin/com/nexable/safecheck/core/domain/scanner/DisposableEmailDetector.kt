package com.nexable.safecheck.core.domain.scanner

/**
 * Disposable email detection using a comprehensive database of known providers.
 */
object DisposableEmailDetector {
    
    // Comprehensive list of known disposable email domains
    private val disposableDomains = setOf(
        // Temporary email services
        "10minutemail.com", "10minutemail.net", "20minutemail.com", "temp-mail.org",
        "tempmail.email", "guerrillamail.com", "guerrillamail.org", "sharklasers.com",
        "grr.la", "guerrillamail.biz", "guerrillamail.de", "yopmail.com", "yopmail.fr",
        "mailinator.com", "mailinator.net", "mailinator.org", "mailtrap.io",
        
        // Throwaway email services
        "throwaway.email", "throwaway-email.com", "trashmail.com", "trashmail.org",
        "disposableemailaddresses.com", "throwawayemailaddresses.com",
        "tempail.com", "temp-email.com", "dispostable.com", "spamgourmet.com",
        
        // Anonymous email services  
        "anonbox.net", "anonymail.dk", "anonymbox.com", "hushmail.com",
        "protonmail.com", "protonmail.ch", "tutanota.com", "securenym.net",
        
        // Burner email services
        "burnermail.io", "33mail.com", "anonaddy.com", "simplelogin.io",
        "relay.firefox.com", "duckduckgo.com", "hide.my.email",
        
        // Common disposable providers
        "0-mail.com", "0815.ru", "0clickemail.com", "1chuan.com", "1pad.de",
        "20email.eu", "2prong.com", "30minutemail.com", "3d-painting.com",
        "4warding.com", "4warding.net", "4warding.org", "60minutemail.com",
        "675hosting.com", "675hosting.net", "675hosting.org", "6url.com",
        "7tags.com", "9ox.net", "a-bc.net", "abyssmail.com", "ac20mail.in",
        "acentri.com", "advantimo.com", "afrobacon.com", "ag.us.to",
        "ajaxapp.net", "akapost.com", "akerd.com", "alivance.com",
        
        // More disposable domains
        "antichef.com", "antichef.net", "antireg.ru", "antispam.de",
        "armyspy.com", "artman-conception.com", "asdasd.ru", "atvclub.msk.ru",
        "autosfromus.com", "baxomale.ht.cx", "beefmilk.com", "bigprofessor.so",
        "binkmail.com", "bio-muesli.net", "bloatbox.com", "bobmail.info",
        "bofthew.com", "bouncr.com", "boxformail.in", "brennendesreich.de",
        "broadbandninja.com", "bsnow.net", "bspamfree.org", "bugmenot.com",
        "burstmail.info", "buymoreplays.com", "byom.de", "c2.hu",
        
        // Additional disposable services
        "cachedot.net", "card.zp.ua", "casualdx.com", "cbair.com",
        "ce.mintemail.com", "centermail.com", "centermail.net", "chammy.info",
        "childsavetrust.org", "chogmail.com", "choicemail1.com", "clixser.com",
        "codeandscotch.com", "coieo.com", "coldemail.info", "cool.fr.nf",
        "correo.blogos.net", "cosmorph.com", "courriel.fr.nf", "courrieltemporaire.com",
        "cubiclink.com", "curryworld.de", "cust.in", "dacoolest.com",
        "dandikmail.com", "dayrep.com", "dcemail.com", "deadaddress.com",
        "deadspam.com", "despam.it", "devnullmail.com", "dfgh.net",
        
        // Popular temporary providers
        "digitalsanctuary.com", "discardmail.com", "discardmail.de", "disposableaddress.com",
        "disposableemailaddresses.com", "disposableinbox.com", "disposeamail.com",
        "disposemail.com", "dispostable.com", "dm.dockip.net", "domozmail.com",
        "donemail.ru", "dontreg.com", "dontsendmespam.de", "dotmsg.com",
        "drdrb.net", "dump-email.info", "dumpandjunk.com", "dumpmail.de",
        "dumpyemail.com", "e-mail.com", "e-mail.org", "e4ward.com",
        "easytrashmail.com", "edv.to", "einrot.com", "einrot.de",
        "email60.com", "emaildienst.de", "emailias.com", "emailinfive.com",
        
        // International disposable providers
        "emailmiser.com", "emailtemporanea.com", "emailtemporanea.net", "emailtemporar.ro",
        "emailtemporario.com.br", "emailto.de", "emailwarden.com", "emailx.at.hm",
        "emailxfer.com", "emeil.in", "emeil.ir", "ememail.de", "emil.com",
        "emz.net", "enterto.com", "ephemail.net", "etranquil.com", "etranquil.net",
        "etranquil.org", "evopo.com", "explodemail.com", "eyepaste.com",
        "fakeinbox.com", "fakemailz.com", "fansworldwide.de", "fantasymail.de",
        "fightallspam.com", "filzmail.com", "fizmail.com", "fleckens.hu",
        "flyspam.com", "fookmail.com", "footard.com", "forgetmail.com",
        
        // More comprehensive list
        "fr33mail.info", "frapmail.com", "freeguwop.gearhostpreview.com", "freemails.cf",
        "freemails.ga", "freemails.ml", "freeoyster.com", "freundin.ru",
        "friendlymail.co.uk", "fux0ringduh.com", "garbagemail.org", "garliclife.com",
        "gehensiemirnichtaufdensack.de", "gelitik.in", "get-mail.cf", "get-mail.ga",
        "get-mail.ml", "get-mail.tk", "get2mail.fr", "getairmail.com",
        "getonemail.com", "getonemail.net", "ghosttexter.de", "giantmail.de",
        "girlsundertheinfluence.com", "gishpuppy.com", "gmial.com", "goemailgo.com",
        "gotmail.net", "gotmail.org", "gotti.otherinbox.com", "great-host.in",
        "greensloth.com", "grr.la", "gsrv.co.uk", "guerillamail.org",
        
        // Additional temporary services
        "h.mintemail.com", "h8s.org", "hacccc.com", "haltospam.com",
        "harakirimail.com", "hartbot.de", "hatespam.org", "headstrong.de",
        "herp.in", "hidemail.de", "hidzz.com", "hmamail.com", "hochsitze.com",
        "hopemail.biz", "hotpop.com", "howify.com", "hulapla.de", "ieh-mail.de",
        "ikbenspamvrij.nl", "imails.info", "imgof.com", "imstations.com",
        "inboxalias.com", "inboxclean.com", "inboxclean.org", "incognitomail.com",
        "incognitomail.net", "incognitomail.org", "infocom.zp.ua", "insorg-mail.info",
        "instant-mail.de", "instantemailaddress.com", "instantlyemail.com", "ip6.li",
        "irish2me.com", "iwi.net", "j-p.us", "jb55.si", "jetable.com",
        
        // More international providers
        "jetable.fr.nf", "jetable.net", "jetable.org", "jnxjn.com", "jourrapide.com",
        "jsrsolutions.com", "junk1e.com", "kaspop.com", "keepmymail.com", "killmail.com",
        "killmail.net", "klzlk.com", "kook.ml", "koszmail.pl", "kurzepost.de",
        "lawlita.com", "leeching.net", "letthemeatspam.com", "lhsdv.com",
        "lifebyfood.com", "link2mail.net", "litedrop.com", "lol.ovpn.to",
        "lopl.co.cc", "lortemail.dk", "lr78.com", "lroid.com", "lukop.dk",
        "m4ilweb.info", "maboard.com", "mail-filter.com", "mail-temporaire.fr",
        "mail.by", "mail.mezimages.net", "mail.zp.ua", "mail114.net",
        "mail1a.de", "mail21.cc", "mail2rss.org", "mail333.com",
        
        // Final batch of disposable domains
        "mail4trash.com", "mailbidon.com", "mailbiz.biz", "mailblocks.com",
        "mailbucket.org", "mailcat.biz", "mailcatch.com", "mailde.de",
        "mailde.info", "maildu.de", "maileater.com", "mailed.ro",
        "mailexpire.com", "mailforspam.com", "mailfreeonline.com", "mailguard.me",
        "mailhz.me", "mailimate.com", "mailin8r.com", "mailinatar.com",
        "mailinator.com", "mailinatorr.com", "mailinator.net", "mailinator.org",
        "mailinator2.com", "mailismagic.com", "mailme.lv", "mailme24.com",
        "mailmoat.com", "mailnator.com", "mailnesia.com", "mailnull.com",
        "mailorg.org", "mailpick.biz", "mailrock.biz", "mailscrap.com",
        "mailshell.com", "mailsiphon.com", "mailsnare.net", "mailtemp.info",
        "mailtome.de", "mailtothis.com", "mailtrash.net", "mailtv.net",
        "mailtv.tv", "mailzilla.com", "mailzilla.org", "makemetheking.com",
        "mamber.net", "manifestgenerator.com", "manybrain.com", "mbx.cc",
        "mciek.com", "mega.zik.dj", "meinspamschutz.de", "meltmail.com",
        "messagebeamer.de", "mierdamail.com", "mintemail.com", "moburl.com",
        "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf", "monumentmail.com",
        "mt2009.com", "mt2014.com", "mycard.net.ua", "mycleaninbox.net",
        "mymail-in.net", "mymailoasis.com", "mypartyclip.de", "myphantomemail.com",
        "myspaceinc.com", "myspaceinc.net", "myspaceinc.org", "myspacepimpedup.com",
        "mytrashmail.com", "nabuma.com", "neomailbox.com", "nepwk.com",
        "nervmich.net", "nervtmich.net", "netmails.com", "netmails.net",
        "netzidiot.de", "neverbox.com", "no-spam.ws", "nobulk.com",
        "noclickemail.com", "nogmailspam.info", "nomail.xl.cx", "nomail2me.com",
        "nomorespamemails.com", "nonspam.eu", "nonspammer.de", "noref.in",
        "nospam.ze.tc", "nospam4.us", "nospamfor.us", "nospamthanks.info",
        "notmailinator.com", "notsharingmy.info", "nowhere.org", "nowmymail.com",
        "nurfuerspam.de", "nus.edu.sg", "nwldx.com", "objectmail.com",
        "obobbo.com", "odnorazovoe.ru", "oneoffemail.com", "onewaymail.com",
        "onlatedotcom.info", "online.ms", "oopi.org", "ordinaryamerican.net",
        "otherinbox.com", "ovpn.to", "owlpic.com", "pancakemail.com",
        "paplease.com", "pcusers.otherinbox.com", "pjkedy.com", "plexolan.de",
        "poczta.onet.pl", "politikerclub.de", "poofy.org", "pookmail.com",
        "privacy.net", "privymail.de", "proxymail.eu", "prtnx.com",
        "putthisinyourspamdatabase.com", "pwrby.com", "recode.me", "reconmail.com",
        "recursor.net", "recyclethis.net", "rejectmail.com", "reliable-mail.com",
        "repulsiveemailaddress.com", "rhyta.com", "riddermark.de", "rklips.com",
        "rmqkr.net", "rozara.com", "s0ny.net", "safe-mail.net", "safersignup.de",
        "safetymail.info", "safetypost.de", "sandelf.de", "saynotospams.com",
        "selfdestructingmail.com", "sendspamhere.de", "sharklasers.com", "shieldedmail.com",
        "shitmail.me", "shitware.nl", "shmeriously.com", "shortmail.net",
        "sibmail.com", "sinnlos-mail.de", "slapsfromlastnight.com", "slaskpost.se",
        "smashmail.de", "smellfear.com", "snakemail.com", "sneakemail.com",
        "snkmail.com", "sofimail.com", "sofort-mail.de", "sogetthis.com",
        "soodonims.com", "spam.la", "spamail.de", "spambob.com", "spambob.net",
        "spambob.org", "spambog.com", "spambog.de", "spambog.ru", "spambox.us",
        "spamcannon.com", "spamcannon.net", "spamcon.org", "spamcorptastic.com",
        "spamcowboy.com", "spamcowboy.net", "spamcowboy.org", "spamday.com",
        "spamex.com", "spamfree24.com", "spamfree24.de", "spamfree24.eu",
        "spamfree24.net", "spamfree24.org", "spamgoes.com", "spamgourmet.com",
        "spamgourmet.net", "spamgourmet.org", "spamhole.com", "spami.spam.ro",
        "spaminator.de", "spamkill.info", "spaml.com", "spaml.de", "spammotel.com",
        "spamobox.com", "spamoff.de", "spamslicer.com", "spamspot.com",
        "spamthis.co.uk", "spamthisplease.com", "spamtrail.com", "spamtroll.net",
        "speed.1s.fr", "spoofmail.de", "squizzy.de", "ssoia.com", "startkeys.com",
        "stinkefinger.net", "stop-my-spam.com", "stuffmail.de", "supermailer.jp",
        "superrito.com", "suremail.info", "teewars.org", "teleworm.com",
        "teleworm.us", "temp-mailbox.com", "tempalias.com", "tempe-mail.com",
        "tempemail.biz", "tempemail.com", "tempinbox.co.uk", "tempinbox.com",
        "tempmail.eu", "tempmail.it", "tempmail2.com", "tempmaildemo.com",
        "tempmailer.com", "tempmailer.de", "tempomail.fr", "temporarily.de",
        "temporarioemail.com.br", "temporaryemail.net", "temporaryforwarding.com",
        "temporaryinbox.com", "temporarymailaddress.com", "tempthe.net", "thankyou2010.com",
        "thc.st", "thecloudindex.com", "thelimestones.com", "thisisnotmyrealemail.com",
        "thismail.net", "throwam.com", "thrma.com", "tilien.com", "tittbit.in",
        "toomail.biz", "topranklist.de", "tradermail.info", "trash-amil.com",
        "trash-mail.at", "trash-mail.com", "trash-mail.de", "trash2009.com",
        "trashdevil.com", "trashdevil.de", "trashemail.de", "trashmail.at",
        "trashmail.com", "trashmail.de", "trashmail.me", "trashmail.net",
        "trashmail.org", "trashmail.ws", "trashmailer.com", "trashymail.com",
        "trashymail.net", "trbvm.com", "trialmail.de", "trickmail.net",
        "trillianpro.com", "tryalert.com", "turual.com", "twinmail.de",
        "twoweirdtricks.com", "txtadvertise.com", "uber.space", "uggsrock.com",
        "umail.net", "upliftnow.com", "uplipht.com", "uroid.com", "us.af",
        "venompen.com", "veryrealemail.com", "viditag.com", "viewcastmedia.com",
        "viewcastmedia.net", "viewcastmedia.org", "vomoto.com", "vubby.com",
        "walala.org", "walkmail.net", "wasteland.rfc822.org", "webemail.me",
        "webm4il.info", "webuser.in", "wh4f.org", "whyspam.me", "willselfdestruct.com",
        "winemaven.info", "wronghead.com", "wuzup.net", "wuzupmail.net",
        "www.e4ward.com", "www.gishpuppy.com", "www.mailinator.com", "xagloo.com",
        "xemaps.com", "xents.com", "xmaily.com", "xoxy.net", "yapped.net",
        "yeah.net", "yep.it", "yogamaven.com", "yomail.info", "yopmail.com",
        "yopmail.fr", "yopmail.net", "youmailr.com", "yourdomain.com",
        "ypmail.webredirect.org", "yuurok.com", "zehnminutenmail.de", "zippymail.info",
        "zoemail.net", "zoemail.org", "zomg.info"
    )
    
    // Known provider patterns for better detection
    private val disposablePatterns = listOf(
        Regex("\\d+min(ute)?mail\\.(com|org|net)"),
        Regex("temp.*mail\\.(com|org|net)"),
        Regex(".*mail.*temp.*\\.(com|org|net)"),
        Regex("disposable.*\\.(com|org|net)"),
        Regex("throw.*away.*\\.(com|org|net)"),
        Regex(".*guerr?illa.*\\.(com|org|net)"),
        Regex(".*trash.*mail.*\\.(com|org|net)")
    )
    
    /**
     * Analyzes an email address for disposable provider detection.
     */
    suspend fun analyze(email: String): DisposableEmailAnalysis {
        val domain = EmailParser.extractDomain(email).lowercase()
        
        if (domain.isEmpty()) {
            return DisposableEmailAnalysis(
                email = email,
                domain = domain,
                isDisposable = false
            )
        }
        
        // Check exact domain match
        val exactMatch = disposableDomains.contains(domain)
        if (exactMatch) {
            return DisposableEmailAnalysis(
                email = email,
                domain = domain,
                isDisposable = true,
                disposableService = domain,
                confidence = 1.0,
                isTemporary = true,
                providerType = classifyProviderType(domain)
            )
        }
        
        // Check pattern matches
        val patternMatch = disposablePatterns.any { pattern ->
            pattern.matches(domain)
        }
        
        if (patternMatch) {
            return DisposableEmailAnalysis(
                email = email,
                domain = domain,
                isDisposable = true,
                disposableService = domain,
                confidence = 0.85,
                isTemporary = true,
                providerType = DisposableProviderType.TEMPORARY
            )
        }
        
        // Check subdomain patterns
        val subdomainMatch = checkSubdomainPatterns(domain)
        if (subdomainMatch.isDisposable) {
            return subdomainMatch.copy(email = email)
        }
        
        // Check for suspicious characteristics
        val suspiciousAnalysis = analyzeSuspiciousCharacteristics(domain)
        
        return DisposableEmailAnalysis(
            email = email,
            domain = domain,
            isDisposable = suspiciousAnalysis.isSuspicious,
            disposableService = if (suspiciousAnalysis.isSuspicious) domain else null,
            confidence = suspiciousAnalysis.confidence,
            isTemporary = suspiciousAnalysis.isSuspicious,
            providerType = if (suspiciousAnalysis.isSuspicious) DisposableProviderType.UNKNOWN else DisposableProviderType.UNKNOWN
        )
    }
    
    private fun classifyProviderType(domain: String): DisposableProviderType {
        return when {
            domain.contains("temp") || domain.contains("minute") -> DisposableProviderType.TEMPORARY
            domain.contains("guerr") || domain.contains("mailinator") -> DisposableProviderType.GUERRILLA
            domain.contains("forward") || domain.contains("relay") -> DisposableProviderType.FORWARDING
            domain.contains("alias") || domain.contains("hide") -> DisposableProviderType.ALIAS
            else -> DisposableProviderType.TEMPORARY
        }
    }
    
    private fun checkSubdomainPatterns(domain: String): DisposableEmailAnalysis {
        // Check if it's a subdomain of a known disposable service
        val parts = domain.split(".")
        if (parts.size >= 3) {
            val parentDomain = parts.drop(1).joinToString(".")
            if (disposableDomains.contains(parentDomain)) {
                return DisposableEmailAnalysis(
                    email = "",
                    domain = domain,
                    isDisposable = true,
                    disposableService = parentDomain,
                    confidence = 0.9,
                    isTemporary = true,
                    providerType = classifyProviderType(parentDomain)
                )
            }
        }
        
        return DisposableEmailAnalysis(
            email = "",
            domain = domain,
            isDisposable = false
        )
    }
    
    private fun analyzeSuspiciousCharacteristics(domain: String): SuspiciousAnalysis {
        var suspicionScore = 0.0
        
        // Check for suspicious keywords
        val suspiciousKeywords = listOf(
            "temp", "throw", "disposable", "fake", "trash", "spam", "junk",
            "guerrilla", "mailinator", "anonymous", "hide", "privacy"
        )
        
        for (keyword in suspiciousKeywords) {
            if (domain.contains(keyword, ignoreCase = true)) {
                suspicionScore += 0.3
            }
        }
        
        // Check for numbers suggesting temporary nature
        if (domain.matches(Regex(".*\\d+(min|hour|day).*"))) {
            suspicionScore += 0.4
        }
        
        // Check for very short domains
        if (domain.length < 8) {
            suspicionScore += 0.1
        }
        
        // Check for many hyphens or numbers
        val hyphenCount = domain.count { it == '-' }
        val numberCount = domain.count { it.isDigit() }
        
        if (hyphenCount > 2) suspicionScore += 0.2
        if (numberCount > 3) suspicionScore += 0.2
        
        val isSuspicious = suspicionScore >= 0.5
        val confidence = if (isSuspicious) suspicionScore.coerceAtMost(0.8) else 0.0
        
        return SuspiciousAnalysis(isSuspicious, confidence)
    }
    
    private data class SuspiciousAnalysis(
        val isSuspicious: Boolean,
        val confidence: Double
    )
    
    /**
     * Checks if a domain is in the disposable list.
     */
    fun isDomainDisposable(domain: String): Boolean {
        return disposableDomains.contains(domain.lowercase())
    }
    
    /**
     * Gets the total number of known disposable domains.
     */
    fun getDisposableDomainCount(): Int {
        return disposableDomains.size
    }
}
