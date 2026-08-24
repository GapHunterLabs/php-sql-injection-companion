package dev.gaphunter.phpsqlinjectioncompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import dev.gaphunter.phpsqlinjectioncompanion.detect.SqlInjectionScanner
import dev.gaphunter.phpsqlinjectioncompanion.review.ReviewPrompt

/**
 * Flags `mysqli_query`/`->query`/`->exec` calls whose SQL argument
 * contains interpolated or concatenated variable data -- see
 * [SqlInjectionScanner] for the full reasoning. Runs via [checkFile]
 * (whole-file text scan) -- see `build.gradle.kts` for why no
 * PHP-language PSI dependency is taken.
 */
class SqlInjectionInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
        private val PHP_FILE_NAME = Regex("""^[^.]+\.php$""", RegexOption.IGNORE_CASE)
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val virtualFile = file.virtualFile ?: return null
        if (!PHP_FILE_NAME.matches(virtualFile.name)) return null

        val text = file.text
        if (text.length > MAX_FILE_LENGTH) return null

        val hits = SqlInjectionScanner.scan(text)
        if (hits.isEmpty()) return null

        val document = file.viewProvider.document ?: return null
        val problems = mutableListOf<ProblemDescriptor>()

        for (hit in hits) {
            if (hit.lineNumber - 1 !in 0 until document.lineCount) continue
            val lineStartOffset = document.getLineStartOffset(hit.lineNumber - 1)
            val absoluteStart = lineStartOffset + hit.columnStart
            val absoluteEnd = lineStartOffset + hit.columnEnd
            val anchor = leafElementAt(file, absoluteStart) ?: continue
            val anchorStart = anchor.textRange.startOffset
            val relativeRange = TextRange(
                (absoluteStart - anchorStart).coerceAtLeast(0),
                (absoluteEnd - anchorStart).coerceAtMost(anchor.textLength),
            )
            if (relativeRange.startOffset >= relativeRange.endOffset) continue

            problems += manager.createProblemDescriptor(
                anchor,
                relativeRange,
                "This SQL query string is interpolated/concatenated with a variable instead of using a prepared " +
                    "statement placeholder -- if any part comes from untrusted input, this is a SQL injection " +
                    "vulnerability (CWE-89). Use a parameterized query (?, :name) with bind_param()/execute() instead",
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
                isOnTheFly,
            )

            ReviewPrompt.recordHit(file.project, "${virtualFile.path}:${hit.lineNumber}")
        }

        return if (problems.isEmpty()) null else problems.toTypedArray()
    }

    private fun leafElementAt(file: PsiFile, startOffset: Int): PsiElement? {
        if (startOffset < 0 || startOffset >= file.textLength) return null
        var element = file.findElementAt(startOffset) ?: return file
        while (element.firstChild != null) {
            element = element.firstChild
        }
        return element
    }
}
