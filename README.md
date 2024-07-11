# bomsquad.vulndb

'bomsquad.vulndb' implements models and APIs for ingesting National Vulnerability Database and OSV datasets
into a relational data store, and cross-querying the datasets.

vulndb is initially envisioned as a research tool for delving into correlations between these datasets. It
may evolve to incorporate additional datasets, or serve further use cases as we follow this research.

## Pre-requisites

1. You will need poetry and poethepoet installed to build from source. pyenv or another environment
   manager is recommended.
2. You may optionally acquire an API key for the National Vulnerability Database

## Installation

1. Copy src/bomsquad/vulndb/config.toml to ~/.vulndb/config.toml and edit to match your evironment
2. Create the database instance:
```
$ vulndb admin create
```

## CLI

The vulndb cli exposes the following commands:

### admin

#### create

```
$ vulndb admin create --help

 Usage: vulndb admin create [OPTIONS]

 Create schema, tables, indices, and user for active configuration.

╭─ Options ────────────────────────────────────╮
│ --help          Show this message and exit.  │
╰──────────────────────────────────────────────╯
```

#### drop

```
$ vulndb admin drop --help

 Usage: vulndb admin drop [OPTIONS]

 Drop schema, tables, indices, and user for active configuration.

╭─ Options ───────────────────────────────────────────────────────────────────╮
│ --show-only    Show script, but do not execute      [default: no-show-only] │
│ --help         Show this message and exit.                                  │
╰─────────────────────────────────────────────────────────────────────────────╯
```


### nvd

#### ingest

Ingest Vulnerability (CVE) and Product (CPE) records from the National Vulnerability Database (https://nvd.nist.gov).

```
$ vulndb nvd ingest --help
Usage: vulndb nvd ingest [OPTIONS]

Options:
  --scope TEXT      Ingest only cve or cpe
  --update    --no-update             Acquire records newer than current data [default: no-update]
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
