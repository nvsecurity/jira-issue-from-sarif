# NightVision to Jira Integration

This repository contains scripts and configurations to interact with Jira and manage project vulnerabilities using NightVision SARIF reports.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
4. [Usage](#usage)
    - [Create Jira API Token](#create-jira-api-token)
    - [Find Jira Project ID](#find-jira-project-id)
    - [Create Tickets from SARIF](#create-tickets-from-sarif)
5. [License](#license)

## Overview

This repository automates the process of creating Jira tickets based on vulnerabilities found by NightVision. It includes scripts to fetch Jira project IDs, convert SARIF reports to Jira issues, and a sample OpenAPI specification.

> NightVision's CLI files Jira tickets from a scan with `nightvision export jira`, and the built-in Jira status sync (configured in the NightVision app) updates a linked finding's resolution when its Jira issue changes status. This script is an alternative that files tickets from a SARIF file, for workflows that already produce SARIF.

## Prerequisites

- Python 3.x
- Jira account and API token
- [NightVision](https://app.nightvision.net/?signup=1) account

## Setup

1. **Clone the repository:**
   ```sh
   git clone https://github.com/nvsecurity/jira-issue-from-sarif.git
   cd jira-issue-from-sarif
   ```

2. **Install required packages:**
   ```sh
   pip install jira
   ```
   (`argparse` is part of the Python standard library and does not need to be installed.)

3. **Set environment variables:**
   ```sh
   export JIRA_URL='your_jira_url'
   export JIRA_USER_EMAIL='your_jira_user_email@example.com'
   export JIRA_API_TOKEN='your_jira_api_token'   # see Create Jira API Token below

   export JIRA_PROJECT_ID='your_jira_project_id' # project id or key; see Find Jira Project ID below
   export JIRA_ISSUE_TYPE='your_jira_issue_type' # optional, defaults to 'Task'
   export JIRA_COMPONENT='your_jira_component'   # optional
   ```

   All environment variables can be passed as arguments to the python scripts. See the corresponding sections.

   See how to get Jira API Token in the next section.

### Create Jira API Token

1. Go to [Jira API tokens](https://id.atlassian.com/manage-profile/security/api-tokens).
2. Create a new API token and copy it.

## Usage

### Find Jira Project ID

`--project-id` / `JIRA_PROJECT_ID` accepts either a numeric project id or a
project key (for example `NV`); a key is resolved to its id automatically. This
lookup is therefore optional when you already know the project key.

1. Run the following command to list Jira Project IDs:
   ```sh
   python get-jira-project-id.py
   ```
   Usage:
   ```
   usage: python get-jira-project-id.py [-h] --url URL --email EMAIL --token TOKEN

   Create Jira tickets from SARIF report.

   optional arguments:
   -h, --help     show this help message and exit

   Jira server credentials:
   --url URL      Jira server URL (JIRA_URL environment variable)
   --email EMAIL  Jira user email (JIRA_USER_EMAIL environment variable)
   --token TOKEN  Jira API token (JIRA_API_TOKEN environment variable)
   ```

2. Select the Jira Project ID you need.
Example output:
   ```
   Projects Available: 2

   1
   Project ID: 10001
   Name      : NightVision
   Key       : NV

   2
   Project ID: 10004
   Name      : NV Sales
   Key       : NS
   ```

### Create Tickets from SARIF

1. Export NightVision SARIF report for a specific scan:
   ```sh
   nightvision export sarif -s "your_scan_id" --swagger-file "./your/swagger/file/path.yaml"
   ```

   This should create a `results.sarif` file in your current directory.


2. Create Jira tickets from the SARIF report:
   ```sh
   python sarif-to-jira.py -p "your_project_id"
   ```

   Usage:
   ```
   usage: python sarif-to-jira.py [-h] --url URL --email EMAIL --token TOKEN -p PROJECT-ID -i TYPE -c COMPONENT
                                  [--sarif-file SARIF_FILE] [--dry-run] [--max-issues N]

   Create Jira tickets from a NightVision SARIF report (deduped, severity-mapped).

   optional arguments:
   -h, --help            show this help message and exit

   Jira server credentials:
   --url URL             Jira server URL (JIRA_URL environment variable)
   --email EMAIL         Jira user email (JIRA_USER_EMAIL environment variable)
   --token TOKEN         Jira API token (JIRA_API_TOKEN environment variable)

   Issue properties:
   -p PROJECT-ID, --project-id PROJECT-ID
                           Jira project id or key (JIRA_PROJECT_ID environment variable)
   -i TYPE, --issue-type TYPE
                           Issue type - defaults to 'Task' (JIRA_ISSUE_TYPE environment variable)
   -c COMPONENT, --component COMPONENT
                           Issue component (JIRA_COMPONENT environment variable)

   Run options:
   --sarif-file SARIF_FILE
                           Path to the SARIF report - defaults to 'results.sarif'
   --dry-run               Report what would be created without creating any Jira issues
                           (still connects to Jira to classify create vs skip)
   --max-issues N          Stop after N issues are created (in dry-run, after N would be created)
   ```

### De-duplication and severity

Each ticket this script creates is tagged with two Jira labels: a constant
`nightvision` label and a per-finding `nv-fingerprint:<key>` label. Before creating a
ticket the script searches the project for that `nv-fingerprint:<key>` label and skips the
finding if a ticket already exists. As a result:

- Running the script repeatedly against the same scan creates each ticket **once**;
  re-runs only fill gaps. (Previously every run created a fresh duplicate of every
  finding.) Tickets are never updated or closed by this script.
- The correlation key is the durable `nightvision-fingerprint` emitted in the SARIF
  when present, and a best-effort hash of the finding's class, source location, and
  endpoint otherwise. Note: SARIF produced by different NightVision producers
  (CLI vs platform download/email) may not yet share the same key, so a duplicate
  can appear once across producers until fingerprint parity lands.
- Finding severity (`nightvision-risk`) is mapped to a Jira priority
  (CRITICAL -> Highest, HIGH -> High, MEDIUM -> Medium, LOW -> Low, INFO -> Lowest).
  The priority is applied only if your Jira priority scheme defines that name;
  otherwise it is omitted rather than failing the create.

**Upgrading from a version without `nv-fingerprint:` labels.** De-duplication
matches on the `nv-fingerprint:<key>` label, which earlier versions of this script
did not attach. The first run after upgrading will not recognize tickets created by
an older version, so it will create one new (deduped) ticket per overlapping
finding. If you have run an older version against a Jira project you want to keep
clean, relabel or close those tickets first, or expect a one-time duplicate set on
that first run.

Use `--dry-run` to preview what would be created, and `--max-issues N` as a safety
cap on large reports. Note that `--dry-run` still connects to Jira and runs the
per-finding dedup search so it can report would-create vs would-skip; it only
suppresses ticket creation, so it requires valid credentials and a reachable
project.
