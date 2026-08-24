<?php
// Demo data for PHP SQL Injection Companion — used with
// `./gradlew runIde` to capture the real Marketplace screenshot. Open
// this file, the warning should appear on the mysqli_query() line.

function find_user($conn, $id) {
    // Interpolated query string -- FLAGGED.
    return mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
}

function find_user_safely($pdo, $id) {
    // Prepared statement placeholder -- NOT flagged.
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}
