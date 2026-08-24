<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# PHP SQL Injection Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Warning on `mysqli_query`/`->query`/`->exec` calls whose SQL
  argument is interpolated or concatenated with a variable instead
  of a prepared-statement placeholder -- CWE-89, not covered by "PHP
  Inspections (EA Extended)".
- 100% static text analysis, no PHP plugin dependency, no network
  calls, no telemetry. Free.

[Unreleased]: https://github.com/GapHunterLabs/php-sql-injection-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/php-sql-injection-companion/commits/0.1.0
