import argparse
import json

from jira import JIRA, JIRAError

from envdefault import EnvDefault


def main(args):
    # Jira server credentials
    jira_url = args.url
    jira_user_email = args.email
    jira_api_token = args.token

    assert jira_url, "JIRA_URL not specified."
    assert jira_user_email, "JIRA_USER_EMAIL not specified."
    assert jira_api_token, "JIRA_API_TOKEN not specified."

    # Jira Issue properties
    jira_project_id = args.project
    jira_issue_type = args.type
    jira_component_name = args.component

    assert jira_project_id, "JIRA_PROJECT_ID not specified."

    # Connect to Jira
    jira = JIRA(
        basic_auth=(jira_user_email, jira_api_token), options={"server": jira_url}
    )

    # Check if Project exists
    try:
        jira.project(id=jira_project_id)
    except JIRAError as e:
        raise ValueError(e.text)

    # Get component id
    component_id = None
    if jira_component_name:
        components = jira.project_components(jira_project_id)
        matched_components = list(
            filter(lambda c: c.name == jira_component_name, components)
        )
        if len(matched_components) == 0:
            raise ValueError(f"Component '{jira_component_name}' not found in Jira.")
        component_id = matched_components[0].id

    # Load SARIF data
    sarif_file = "results.sarif"
    try:
        with open(sarif_file, "r") as file:
            sarif_data = json.load(file)
    except OSError as e:
        raise ValueError(f"Could not read a file '{sarif_file}'")

    # Iterate over findings in SARIF data
    for run in sarif_data["runs"]:
        for result in run["results"]:
            rule_id = result["ruleId"]
            description = next(
                (
                    rule["fullDescription"]["text"]
                    for rule in run["tool"]["driver"]["rules"]
                    if rule["id"] == rule_id
                ),
                "No description available.",
            )

            # Issue details
            issue_dict = {
                "project": {"id": jira_project_id},
                "summary": result["message"]["text"],
                # 'summary': rule_id, # can use for a more specific title
                "description": description,
                "issuetype": {"name": jira_issue_type},
            }

            if component_id:
                issue_dict["components"] = [{"id": component_id}]

            # Create the issue
            new_issue = jira.create_issue(fields=issue_dict)
            print(f"Issue created: {new_issue.key}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python sarif-to-jira.py",
        description="Create Jira tickets from SARIF report.",
    )

    group_jira = parser.add_argument_group("Jira server credentials")
    group_jira.add_argument(
        "--url", action=EnvDefault, envvar="JIRA_URL", dest="url",
        help="Jira server URL",
    )
    group_jira.add_argument(
        "--email", action=EnvDefault, envvar="JIRA_USER_EMAIL", dest="email",
        help="Jira user email",
    )
    group_jira.add_argument(
        "--token", action=EnvDefault, envvar="JIRA_API_TOKEN", dest="token",
        help="Jira API token",
    )

    group_issue = parser.add_argument_group("Issue properties")
    group_issue.add_argument(
        "-p", "--project-id", action=EnvDefault, envvar="JIRA_PROJECT_ID", dest="project", metavar="PROJECT-ID",
        help="Jira Project ID"
    )
    group_issue.add_argument(
        "-i", "--issue-type", action=EnvDefault, envvar="JIRA_ISSUE_TYPE", dest="type", default="Task",
        help="Issue type - defaults to 'Task'",
    )
    group_issue.add_argument(
        "-c", "--component", action=EnvDefault, envvar="JIRA_COMPONENT", dest="component", default="",
        help="Issue component",
    )

    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        print("Error:", e)
        exit(1)
