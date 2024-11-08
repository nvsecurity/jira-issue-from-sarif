import argparse

from jira import JIRA

from envdefault import EnvDefault


def main(args):
    # Jira server credentials
    jira_url = args.url
    jira_user_email = args.email
    jira_api_token = args.token

    assert jira_url, "JIRA_URL not specified."
    assert jira_user_email, "JIRA_USER_EMAIL not specified."
    assert jira_api_token, "JIRA_API_TOKEN not specified."

    # Connect to Jira
    jira = JIRA(
        basic_auth=(jira_user_email, jira_api_token), options={"server": jira_url}
    )

    projects = jira.projects()

    print()
    print("Projects Available:", len(projects))
    print()

    # Print the project ID
    for idx, project in enumerate(projects):
        print(idx + 1)
        print("Project ID:", project.id)
        print("Name      :", project.name)
        print("Key       :", project.key)
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python get-jira-project-id.py",
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

    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        print("Error:", e)
        exit(1)
