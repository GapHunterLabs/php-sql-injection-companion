package dev.gaphunter.phpsqlinjectioncompanion.detect

import dev.gaphunter.phpsqlinjectioncompanion.model.SqlInjectionHit

/**
 * Plain-text line scanner for a PHP file -- flags `mysqli_query(`,
 * `->query(`, or `->exec(` (the `mysqli`/`PDO` query methods) whose
 * SQL string argument contains `$variable` interpolation (double
 * quotes only) or a concatenation with a variable, rather than a
 * prepared-statement placeholder. This is the textbook SQL injection
 * anti-pattern: prepared statements exist precisely so the SQL text
 * and the data are sent to the database separately -- string-building
 * a query defeats that protection entirely, the same class of risk
 * PHP's own community/security guidance (OWASP, PHP: The Right Way)
 * consistently calls out as the #1 PHP injection vector.
 *
 * Confirmed real gap: "PHP Inspections (EA Extended)" (one of the
 * most widely used PHP inspection plugins on Marketplace) does not
 * cover SQL injection through query method parameters -- confirmed by
 * reading its own documented security feature list before building
 * this (it covers `unserialize()`, weak crypto, `extract()`/
 * `parse_str()`, but not this).
 *
 * **v0.1 scope, stated honestly:** plain-text regex matching, not
 * real PHP PSI -- doesn't trace whether the interpolated value
 * actually originates from untrusted input, so interpolation of a
 * hardcoded constant is a possible (rare) false positive. A call
 * whose argument is entirely a static literal, or built with `?`/
 * named placeholders and a separate `bind_param`/`execute` call, is
 * correctly never flagged.
 */
object SqlInjectionScanner {

    private val QUERY_METHOD = Regex("""\b(mysqli_query|->\s*query|->\s*exec)\s*\(""")
    private val INTERPOLATED_ARG = Regex(""""(?:[^"\\]|\\.)*\$\w""")
    private val CONCAT_ARG = Regex("""(["'])(?:[^"'\\]|\\.)*\1\s*\.\s*\$\w""")

    fun scan(text: String): List<SqlInjectionHit> {
        val hits = mutableListOf<SqlInjectionHit>()
        text.lines().forEachIndexed { index, rawLine ->
            val trimmed = rawLine.trimStart()
            if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) return@forEachIndexed

            val callMatch = QUERY_METHOD.find(rawLine) ?: return@forEachIndexed
            val afterCall = rawLine.substring(callMatch.range.last + 1)
            val hasInterpolation = INTERPOLATED_ARG.containsMatchIn(afterCall) || CONCAT_ARG.containsMatchIn(afterCall)
            if (!hasInterpolation) return@forEachIndexed

            val callName = callMatch.groupValues[1].replace(Regex("""\s"""), "")
            hits += SqlInjectionHit(callName, index + 1, callMatch.range.first, callMatch.range.last + 1)
        }
        return hits
    }
}
