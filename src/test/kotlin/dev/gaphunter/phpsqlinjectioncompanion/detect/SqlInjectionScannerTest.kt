package dev.gaphunter.phpsqlinjectioncompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SqlInjectionScannerTest {

    @Test
    fun `flags mysqli_query with interpolated argument`() {
        val code = """mysqli_query(${'$'}conn, "SELECT * FROM users WHERE id = ${'$'}id");"""
        val hits = SqlInjectionScanner.scan(code)
        assertEquals(1, hits.size)
    }

    @Test
    fun `flags PDO-exec with concatenated argument`() {
        val code = """${'$'}pdo->exec('DELETE FROM sessions WHERE id = ' . ${'$'}sessionId);"""
        val hits = SqlInjectionScanner.scan(code)
        assertEquals(1, hits.size)
    }

    @Test
    fun `flags mysqli-object-style query with interpolated argument`() {
        val code = """${'$'}mysqli->query("SELECT * FROM orders WHERE user_id = ${'$'}userId");"""
        val hits = SqlInjectionScanner.scan(code)
        assertEquals(1, hits.size)
    }

    @Test
    fun `does not flag a prepared statement placeholder`() {
        val code = """${'$'}stmt = ${'$'}pdo->prepare("SELECT * FROM users WHERE id = ?");"""
        assertTrue(SqlInjectionScanner.scan(code).isEmpty())
    }

    @Test
    fun `does not flag a plain literal query`() {
        val code = """${'$'}pdo->query("SELECT COUNT(*) FROM users");"""
        assertTrue(SqlInjectionScanner.scan(code).isEmpty())
    }

    @Test
    fun `does not flag a commented-out line`() {
        val code = """// mysqli_query(${'$'}conn, "SELECT * FROM users WHERE id = ${'$'}id");"""
        assertTrue(SqlInjectionScanner.scan(code).isEmpty())
    }
}
