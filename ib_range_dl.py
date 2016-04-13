#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      User
#
# Created:     13/04/2016
# Copyright:   (c) User 2016
# Licence:     <your licence>
#-------------------------------------------------------------------------------
from __future__ import print_function
import requests
import requests.exceptions
import time
import cookielib
import json
import os
import random
import argparse
import sys
import shutil
import urllib


def print_(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()


def fetch(requests_session, url, method='get', data=None, expect_status=200, headers=None):
#    headers = {'user-agent': user_agent}
    headers = {'user-agent': 'test'}

    if headers:
        headers.update(headers)

    for try_num in range(5):
        print_('Fetch', url, '...', end='')

        if method == 'get':
            response = requests_session.get(url, headers=headers, timeout=60)
        elif method == 'post':
            response = requests_session.post(url, headers=headers, data=data, timeout=60)
        else:
            raise Exception('Unknown method')

        print_(str(response.status_code))

        if response.status_code != expect_status and not ok_text_found:
            print_('Problem detected. Sleeping.')
            time.sleep(60)
        else:
            time.sleep(random.uniform(0.5, 1.5))
            return response

    raise Exception('Giving up!')


def save_submissions(requests_session, sid, submission_ids, output_path):
    """
    Save one Inkbunny submission through the API
    Output to:
        <output_path>/<submission_id>.json
        <output_path>/<submission_id>.<file_number>.<file_name>
    """
    if (submission_ids is type(1)):
        submission_ids = [submission_ids]
    if len(submission_ids) > 100:
        raise Exception('Too many submission ids!')
    if (not os.path.exists(output_path)) and (len(output_path) > 0):
        os.makedirs(output_path)

    # Turn given submission ids list into something the URL can include
    submission_ids_string = ''
    for s in submission_ids:
        submission_ids_string += str(s)+ ','
    submission_ids_string = submission_ids_string[:-1]

    submission_info_url = 'https://inkbunny.net/api_submissions.php?sid=%s&submission_ids=%s' % (sid, submission_ids_string)
    submission_info_response = fetch(requests_session, submission_info_url)
    results = json.loads(submission_info_response.text)
    #print('results: %s' % (results))

    assert(len(results['submissions']) == len(submission_ids))
    # Save each submission
    for submission_info in results['submissions']:
        submission_id = submission_info['submission_id']

        # Save files
        for submission_file in submission_info['files']:
            #print('submission_file: %s' % (submission_file))
            file_full_url = submission_file['file_url_full']
            original_file_name = submission_file['file_name']
            file_order = submission_file['submission_file_order']
            download_filepath = os.path.join(output_path, '%s.%s.%s' % (submission_id, file_order, original_file_name))
            assert not os.path.exists(download_filepath)
            urllib.urlretrieve(file_full_url, download_filepath)#TODO Replace this call with something better
##            file_full_response = fetch(requests_session, file_full_url)
##            with open(download_filepath, 'w') as f:
##                # http://stackoverflow.com/questions/13137817/how-to-download-image-using-requests
##                #shutil.copyfileobj(file_full_response.raw, f)
##                f.write(file_full_response.content)

        # Save JSON
        json_filepath = os.path.join(output_path, '%s.json' % (submission_id))
        assert not os.path.exists(json_filepath)
        with open(json_filepath, 'w') as f:
            json.dump(submission_info, f)




def inkbunny_api_login(requests_session, login_username, login_password):
    """Log in to the inkbunny API and return the sid (session ID)"""
    login_url ='https://inkbunny.net/api_login.php?username=%s&password=%s' % (login_username, login_password)
    page = fetch(requests_session, login_url)
    login_response_obj = json.loads(page.text)

    if 'error_message' in login_response_obj.keys():
        print('login_response_obj: %s' % (repr(login_response_obj)))
        raise Exception('Error logging in!')
    if login_response_obj['ratingsmask'] != '11111':
        print('login_response_obj: %s' % (repr(login_response_obj)))
        raise Exception('Account not set to view all submissions!')

    sid = login_response_obj['sid']
    print('Inkbunny sid: %s' %  (sid))
    return sid




def main():
    # Handle command line args
    parser = argparse.ArgumentParser()
    parser.add_argument('start_num', help='low end of the range to work over',
                    type=int)
    parser.add_argument('end_num', help='high end of the range to work over',
                    type=int)
    parser.add_argument('username', help='Inkbunny account username',
                    type=str)
    parser.add_argument('password', help='Inkbunny account password',
                    type=str)
    parser.add_argument('output_path', help='Output path',
                    type=str, default='download')
    args = parser.parse_args()
    login_username = args.username
    login_password = args.password
    start_num = args.start_num
    end_num = args.end_num
    output_path = args.output_path
    # Setup requests session
    requests_session = requests.Session()
    requests_session.cookies = cookie_jar = cookielib.MozillaCookieJar('cookies.txt')
    # Log in
    sid = inkbunny_api_login(requests_session,
        login_username,
        login_password
    )

    # Minor error-checking on input range
    start_num, end_num = abs(start_num), abs(end_num)# Prevent negatives
    if start_num > end_num:# Handle case where beginning is greater than end
        start_num, end_num = end_num, start_num

    if start_num == end_num:# Handle case of only one submission to save
        nums = [start_num]
        save_submissions(requests_session,
            sid=sid,
            submission_ids=nums,
            output_path=output_path,
        )

    else:# Process range of submissions
        # Break up range into groups of 100
        for low_id in xrange(start_num, end_num, 100):
            # Start with a number x
            high_id = low_id + 99# Add 99 to the number x
            if high_id > end_num:# If the number x+99 is above the maximum, subtract the difference
                high_id -= (high_id - end_num)
            print('low_id: %s, high_id: %s' % (low_id, high_id))
            # Populate groups of 100
            nums = list(range(int(low_id), int(high_id) + 1))# populate the list with numbers from x to x+99
            #print(nums)
            assert(len(nums) <= 100)#
            save_submissions(requests_session,
                sid=sid,
                submission_ids=nums,
                output_path=output_path,
            )



if __name__ == '__main__':
    main()
