# PHP SQL Injection Companion

Warning on `mysqli_query(`, `->query(`, or `->exec(` (the
`mysqli`/`PDO` query methods) whose SQL string argument contains
`$variable` interpolation or a concatenation with a variable, rather
than a prepared-statement placeholder. This is the textbook SQL
injection anti-pattern: prepared statements exist precisely so the SQL
text and the data are sent to the database separately — string-
building a query defeats that protection entirely.

Confirmed real gap: "PHP Inspections (EA Extended)" (one of the most
widely used PHP inspection plugins on Marketplace) covers
`unserialize()`, weak crypto, `extract()`/`parse_str()`, and several
other security patterns, but not SQL injection through query method
parameters — confirmed by reading its own documented security feature
list before building this.

## Why it exists

```php
mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
```

compiles and runs fine — until `$id` ever contains something like
`"1 OR 1=1"` from user input, at which point it's a full SQL injection.

## Why built this way

- **100% static text analysis** — a regex-based line scanner, not a
  real PHP parser, so it works whether the PHP plugin is installed or
  not.

## v0.1 scope — stated honestly, not exhaustively

Doesn't trace whether the interpolated value actually originates from
untrusted input, so interpolation of a hardcoded constant is a
possible (rare) false positive. A call whose argument is entirely a
static literal, or built with `?`/named placeholders and a separate
`bind_param`/`execute` call, is correctly never flagged.

## Usage

Open any `.php` file. A `mysqli_query`/`->query`/`->exec` call with an
interpolated/concatenated SQL string shows a warning.

## Enterprise / Team Licensing

Need enterprise features, custom rules, or team licensing? Contact us at
**gaphunterlabs@gmail.com**.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
