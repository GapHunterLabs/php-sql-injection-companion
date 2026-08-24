# Demo data — PHP SQL Injection Companion

For capturing the real Marketplace screenshot:

1. `./gradlew runIde`
2. Open `demo/user_repository.php` as a scratch/standalone file (or
   drop it into any sandbox project) inside the sandbox IDE.
3. The `mysqli_query($conn, "SELECT * FROM users WHERE id = $id")`
   call inside `find_user` shows the warning — hover it for the
   tooltip. `find_user_safely`'s prepared statement stays clean, for
   contrast.
4. Enter Full Screen (`View > Appearance > Enter Full Screen`), capture
   with `Win+Shift+S`, save directly to `docs/screenshots/` in this
   repo.
