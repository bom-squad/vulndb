# bomsquad.vulndb

'bomsquad.vulndb' implements models and APIs for ingesting National Vulnerability Database and OSV datasets
into a relational data store, and cross-querying the datasets.

vulndb is initially envisioned as a research tool for delving into correlations between these datasets. It
may evolve to incorporate additional datasets, or serve further use cases as we follow this research.

## Pre-requisites

1. You will need a postgres database installed. See 'admin' CLI commands below to provision
   or generate provisioning SQL commands based on the database configuration. If you are running as
   a user with administrative database privileges to a local db instance, and you have configured
   username, password, and datbase in an active vulndb configuration, the quick start command is 'vulndb admin create_all'.
2. You will need poetry and poethepoet installed to build from source. pyenv or another environment
   manager is recommended.
3. You may optionally acquire an API key for the National Vulnerability Database

## Installation

1. Run the create.sql as the owning user:
```
$ sql -U <username> -d <database> -a -f db/create.sql
```
3. Copy config.toml to ~/.vulndb/config.toml and edit to match your evironment

## CLI

The vulndb cli exposes the following commands:

### admin

#### create_all

```
$ vulndb admin create_all --help

 Usage: vulndb admin create_all [OPTIONS]

 Create schema, tables, indices, and user for active configuration.

╭─ Options ────────────────────────────────────╮
│ --help          Show this message and exit.  │
╰──────────────────────────────────────────────╯
```

#### create_db

```
$ vulndb admin create_db --help

 Usage: vulndb admin create_db [OPTIONS]

 Create database for active configuration.

╭─ Options ───────────────────────────────────────────────────────────────────╮
│ --show-only    Show script, but do not execute      [default: no-show-only] │
│ --help         Show this message and exit.                                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```

#### create_tables

```
$ vulndb admin create_tables --help

 Usage: vulndb admin create_tables [OPTIONS]

 Create tables and indiciates for active configuration.

╭─ Options ───────────────────────────────────────────────────────────────────╮
│ --show-only    Show script, but do not execute      [default: no-show-only] │
│ --help         Show this message and exit.                                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```

#### create_user

```
$ vulndb admin create_user --help

 Usage: vulndb admin create_user [OPTIONS]

 Create user for active configuration.

╭─ Options ───────────────────────────────────────────────────────────────────╮
│ --show-only    Show script, but do not execute      [default: no-show-only] │
│ --help         Show this message and exit.                                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```

#### drop_all

```
$ vulndb admin drop_all --help

 Usage: vulndb admin drop_all [OPTIONS]

 Drop schema, tables, indices, and user for active configuration.

╭─ Options ───────────────────────────────────────────────────────────────────╮
│ --show-only    Show script, but do not execute      [default: no-show-only] │
│ --help         Show this message and exit.                                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```


### nvd

#### ingest

Ingest Vulnerability (CPE) and Product (CPE) records from the National Vulnerability Database (https://nvd.nist.gov).

```
$ vulndb nvd ingest --help
Usage: vulndb nvd ingest [OPTIONS]

Options:
  --scope TEXT      Ingest only cve or cpe
  --offset INTEGER  Offset into available entries to begin wtih  [default: 0]
  --limit INTEGER   Limit the number of entries to ingest
  --help            Show this message and exit.
```

### osv

#### ingest

Ingest records from the Open Source Vulnerability (https://osv.dev) dataset.

```
$ vulndb osv ingest --help
Usage: vulndb osv ingest [OPTIONS]

Options:
  --ecosystem TEXT  Ingest only a single ecosystem
  --offset INTEGER  Offset into available entries to begin wtih  [default: 0]
  --limit INTEGER   Limit the number of entries to ingest
  --help            Show this message and exit.
```

### purl

#### lookup

Perform a lookup for vulnerability records for a given PURL. If the PURL is unversioned, then
all known vulnerabilities associated with the PURL are reported. If the PURL is versioned, then
only applicable vulnerabilities for the specified version are reported.

```
$ vulndb purl lookup --help
 Usage: vulndb purl lookup [OPTIONS] TARGET

╭─ Arguments ───────────────────────────────────╮
│ *    target      TEXT  [default: None]        │
╰───────────────────────────────────────────────╯
╭─ Options ─────────────────────────────────────╮
│ --help          Show this message and exit.   │
╰───────────────────────────────────────────────╯
```

### cve

#### affected-purls

Perform a lookup for PURLs associated with a given CVE. Prints a list of affected packages,
associated identifiers, and affected version ranges.

```
# vulndb cve affected-purls --help
 Usage: vulndb cve affected-purls [OPTIONS] ID

╭─ Arguments ───────────────────────────────────╮
│ *    id      TEXT  [default: None] [required] │
╰───────────────────────────────────────────────╯
╭─ Options ─────────────────────────────────────╮
│ --help          Show this message and exit.   │
╰───────────────────────────────────────────────╯
```

## Testing

There are currently two test suites: Unit and Data Validation.

### Unit Tests

The Unit Test Suite covers (mostly) isolated component tests. A fixture creates a
test dataset, loads it from examples in the tests/example directory hierarchy, and
drops the test database after the test suite executes.

Polyfactory is used for mock data object generation. Factories in use are defined in
tests/factory.py.

```
$ poetry run poe unit_test
```

### Data Validation

The Data Validation Suite iterates through an entire active data set and materializes
each record to ensure that all active entries are compatible with defined schemata.

```
$ poetry run poe data_validation_test
```