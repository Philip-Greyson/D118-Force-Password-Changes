"""Script to flag all Google users inside specific OUs (and all their sub-OUs) to change their password at next sign in.

Does NOT change or reset anyone's current password, it only sets the "changePasswordAtNextLogin" flag on each account.
After it runs, the next time each user signs in with their existing password, Google will make them choose a new one.

Needs the google-api-python-client, google-auth-httplib2 and the google-auth-oauthlib
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

API documentation used:
https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.users.html
https://developers.google.com/workspace/admin/directory/v1/guides/search-users
"""

# importing modules
import os  # needed to check if the token file exists
import time  # used to add a small delay between updates so we don't hit the API rate limits
from datetime import (
    datetime,  # used to get the current time for the start/end of the log
)
from typing import TextIO  # used for the type annotation of the open log file

# google module imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build

# Google API Scopes that will be used. If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/admin.directory.user']  # read/write access to user accounts, needed to list users and set the flag
CREDENTIALS_FILE = 'credentials.json'  # the OAuth client file downloaded from the Google Cloud project
TOKEN_FILE = 'token.json'  # stores the access and refresh tokens, created automatically after the first approval
LOG_FILE = 'passwordChangeLog.txt'  # output log file of everything the script does

# The top level OUs to process. Every user in these OUs AND every sub-OU beneath them will be flagged
# Use the full path starting with a slash, exactly as it appears in Google Admin
TARGET_OUS = ['']

# Safety switch. When True, the script only logs who WOULD be flagged without changing anything in Google
# Run it once with True and review the log, then change to False to actually set the flags
DRY_RUN = True

SKIP_SUSPENDED = True  # if True, suspended accounts are skipped since they can't sign in anyway
EXCLUDED_EMAILS = []  # any specific accounts that should never be flagged even if inside the OUs (service accounts, kiosk accounts, etc). Use full lowercase emails
SLEEP_BETWEEN_UPDATES = 0.1  # seconds to wait between each account update, helps stay under the Directory API write quota when doing thousands of users


def log_message(message: str, log: TextIO) -> None:
    """Print a message to the console and also write it to the log file."""
    print(message)  # print to the console
    print(message, file=log)  # print the same thing to the log file


def get_google_service() -> Resource:
    """Get credentials from the json files, ask for permissions on scope or use existing token approval, then build the directory service."""
    creds = None
    # The token file stores the user's access and refresh tokens, and is created automatically when the authorization flow completes for the first time
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    # If there are no (valid) credentials available, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  # token is just expired, refresh it without needing to log in again
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)  # opens a browser window to approve the scopes
        # Save the credentials for the next run
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    service = build('admin', 'directory_v1', credentials=creds)  # build the "service" connection to the Directory API
    return service


def get_users_in_ou(service: Resource, ou_path: str, log: TextIO) -> list[dict]:
    """Return a list of all user objects in the given OU and every sub-OU beneath it, handling multi-page results from the API."""
    # The orgUnitPath query matches all org unit chains under the target, so sub-OUs are automatically included
    # Wrap the path in single quotes so OU names with spaces work, and escape any apostrophes in the name with a backslash
    escaped_path = ou_path.replace("'", "\\'")
    query = f"orgUnitPath='{escaped_path}'"

    users = []  # list that will hold every user object found
    page_token = None  # None for the first page, then gets filled in with the next page token from each result
    while True:
        try:
            results = service.users().list(customer='my_customer', query=query, maxResults=500, pageToken=page_token, projection='basic').execute()
        except Exception as er:
            log_message(f'ERROR while getting users in {ou_path} from Google Admin: {er}', log)
            break  # stop trying this OU if the query fails, so we don't loop forever

        page_users = results.get('users', [])  # separate just the users list from the rest of the result, empty list if there are none
        users.extend(page_users)  # add this page of users to the overall list
        page_token = results.get('nextPageToken')  # get the token for the next page of results
        if not page_token:  # if there is no next page token, we have gotten every user
            break

    return users


def flag_user(service: Resource, email: str, log: TextIO) -> bool:
    """Set the change password at next login flag on a single user without touching their password, returns True if it succeeded."""
    # Only sending the one field in the body means patch leaves everything else on the account (including the password) unchanged
    body = {'changePasswordAtNextLogin': True}
    try:
        service.users().patch(userKey=email, body=body).execute()
        return True
    except Exception as er:
        log_message(f'ERROR while setting the change password flag on {email}: {er}', log)
        return False


if __name__ == '__main__':  # main file execution
    with open(LOG_FILE, 'w') as log:
        start_time = datetime.now().strftime('%H:%M:%S')
        log_message(f'INFO: Execution started at {start_time}', log)
        if DRY_RUN:
            log_message('INFO: DRY_RUN is True, no accounts will actually be changed. Set DRY_RUN = False to apply the changes', log)

        service = get_google_service()  # connect to the Google Directory API

        excluded = {email.lower() for email in EXCLUDED_EMAILS}  # make a set of the excluded emails, lowercased so the comparison isn't case sensitive
        processed_emails = set()  # tracks emails already handled, in case the target OUs overlap so nobody gets processed twice

        # counters for the summary at the end
        flagged_count = 0
        already_flagged_count = 0
        skipped_count = 0
        error_count = 0

        for ou_path in TARGET_OUS:
            log_message(f'INFO: Getting all users in {ou_path} and its sub-OUs, this may take a while', log)
            ou_users = get_users_in_ou(service, ou_path, log)
            log_message(f'INFO: Found {len(ou_users)} users in {ou_path} and its sub-OUs', log)

            for user in ou_users:
                email = user.get('primaryEmail', '').lower()
                user_ou = user.get('orgUnitPath')  # the actual sub-OU the user is in, just used for logging
                is_suspended = user.get('suspended', False)
                is_already_flagged = user.get('changePasswordAtNextLogin', False)

                if email in processed_emails:  # already handled this person from a different target OU
                    continue
                processed_emails.add(email)

                if email in excluded:  # skip any accounts that are in the exclusion list
                    log_message(f'INFO: Skipping {email} in {user_ou} because it is in the excluded emails list', log)
                    skipped_count += 1
                    continue

                if SKIP_SUSPENDED and is_suspended:  # skip suspended accounts if that option is on
                    log_message(f'DBUG: Skipping {email} in {user_ou} because the account is suspended', log)
                    skipped_count += 1
                    continue

                if is_already_flagged:  # no need to send an update if the flag is already set
                    log_message(f'DBUG: {email} in {user_ou} already has the change password flag set', log)
                    already_flagged_count += 1
                    continue

                if DRY_RUN:  # just log what would happen without making the change
                    log_message(f'INFO: DRY RUN - would flag {email} in {user_ou} to change password at next sign in', log)
                    flagged_count += 1
                    continue

                # actually set the flag on the account
                log_message(f'INFO: Flagging {email} in {user_ou} to change password at next sign in', log)
                success = flag_user(service, email, log)
                if success:
                    flagged_count += 1
                else:
                    error_count += 1
                time.sleep(SLEEP_BETWEEN_UPDATES)  # small pause between updates to stay under the API quota

        # print out a summary of the run
        flagged_label = 'Would be flagged' if DRY_RUN else 'Flagged'  # change the wording of the summary depending on if it was a dry run
        log_message(f'INFO: {flagged_label}: {flagged_count} | Already flagged: {already_flagged_count} | Skipped: {skipped_count} | Errors: {error_count}', log)

        end_time = datetime.now().strftime('%H:%M:%S')
        log_message(f'INFO: Execution ended at {end_time}', log)
