package dev.gaphunter.phpsqlinjectioncompanion.model

data class SqlInjectionHit(val callText: String, val lineNumber: Int, val columnStart: Int, val columnEnd: Int)
