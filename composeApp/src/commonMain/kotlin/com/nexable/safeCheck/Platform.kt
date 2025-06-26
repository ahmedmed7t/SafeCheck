package com.nexable.safeCheck

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform