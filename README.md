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
   pip install argparse jira
   ```

3. **Set environment variables:**
   ```sh
   export JIRA_URL='your_jira_url'
   export JIRA_USER_EMAIL='your_jira_user_email@example.com'
   export JIRA_API_TOKEN='your_jira_api_token'   # see Create Jira API Token below

   export JIRA_PROJECT_ID='your_jira_project_id' # see Find Jira Project ID below
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

   Create Jira tickets from SARIF report.

   optional arguments:
   -h, --help            show this help message and exit

   Jira server credentials:
   --url URL             Jira server URL (JIRA_URL environment variable)
   --email EMAIL         Jira user email (JIRA_USER_EMAIL environment variable)
   --token TOKEN         Jira API token (JIRA_API_TOKEN environment variable)

   Issue properties:
   -p PROJECT-ID, --project-id PROJECT-ID
                           Jira Project ID (JIRA_PROJECT_ID environment variable)
   -i TYPE, --issue-type TYPE
                           Issue type - defaults to 'Task' (JIRA_ISSUE_TYPE environment variable)
   -c COMPONENT, --component COMPONENT
                           Issue component (JIRA_COMPONENT environment variable)
   ```
