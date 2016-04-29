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
import hashlib# Needed to hash file data
import base64 # Needed to do base32 encoding of filenames
import logging
import logging.handlers
import datetime



def setup_logging(log_file_path,timestamp_filename=True,max_log_size=104857600):
    """Setup logging (Before running any other code)
    http://inventwithpython.com/blog/2012/04/06/stop-using-print-for-debugging-a-5-minute-quickstart-guide-to-pythons-logging-module/
    """
    assert( len(log_file_path) > 1 )
    assert( type(log_file_path) == type("") )
    global logger

    # Make sure output dir(s) exists
    log_file_folder =  os.path.dirname(log_file_path)
    if log_file_folder is not None:
        if not os.path.exists(log_file_folder):
            os.makedirs(log_file_folder)

    # Add timetamp for filename if needed
    if timestamp_filename:
        # http://stackoverflow.com/questions/8472413/add-utc-time-to-filename-python
        # '2015-06-30-13.44.15'
        timestamp_string = datetime.datetime.utcnow().strftime("%Y-%m-%d %H.%M.%S%Z")
        # Full log
        log_file_path = add_timestamp_to_log_filename(log_file_path,timestamp_string)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # 2015-07-21 18:56:23,428 - t.11028 - INFO - ln.156 - Loading page 0 of posts for u'mlpgdraws.tumblr.com'
    formatter = logging.Formatter("%(asctime)s - t.%(thread)d - %(levelname)s - ln.%(lineno)d - %(message)s")

    # File 1, log everything
    # https://docs.python.org/2/library/logging.handlers.html
    # Rollover occurs whenever the current log file is nearly maxBytes in length; if either of maxBytes or backupCount is zero, rollover never occurs.
    fh = logging.handlers.RotatingFileHandler(
        filename=log_file_path,
        # https://en.wikipedia.org/wiki/Binary_prefix
        # 104857600 100MiB
        maxBytes=max_log_size,
        backupCount=10000,# Ten thousand should be enough to crash before we reach it.
        )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console output
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logging.info("Logging started.")
    return logger


def add_timestamp_to_log_filename(log_file_path,timestamp_string):
    """Insert a string before a file extention"""
    base, ext = os.path.splitext(log_file_path)
    return base+"_"+timestamp_string+ext



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

        if response.status_code != expect_status:
            print_('Problem detected. Sleeping.')
            time.sleep(60)
        else:
            time.sleep(random.uniform(0.5, 1.5))
            return response

    raise Exception('Giving up!')


def save_file(file_path,data,force_save=False,allow_fail=False):
    counter = 0
    while counter <= 10:
        counter += 1

        if not force_save:
            if os.path.exists(file_path):
                logging.debug("save_file()"" File already exists! "+repr(file_path))
                return
        foldername = os.path.dirname(file_path)
        if len(foldername) != 0:
            if not os.path.exists(foldername):
                try:
                    os.makedirs(foldername)
                except WindowsError, err:
                    pass
        try:
            file = open(file_path, "wb")
            file.write(data)
            file.close()
            return
        except IOError, err:
            logging.exception(err)
            logging.error(repr(file_path))
            time.sleep(1)
            continue
    logging.warning("save_file() Too many failed write attempts! "+repr(file_path))
    if allow_fail:
        return
    else:
        logging.critical("save_file() Passing on exception")
        logging.critical(repr(file_path))
        raise


def appendlist(lines,list_file_path="tumblr_done_list.txt",initial_text="# List of completed items.\n"):
    # Append a string or list of strings to a file; If no file exists, create it and append to the new file.
    # Strings will be seperated by newlines.
    # Make sure we're saving a list of strings.
    if ((type(lines) is type(""))or (type(lines) is type(u""))):
        lines = [lines]
    # Ensure file exists.
    if not os.path.exists(list_file_path):
        list_file_segments = os.path.split(list_file_path)
        list_dir = list_file_segments[0]
        if list_dir:
            if not os.path.exists(list_dir):
                os.makedirs(list_dir)
        nf = open(list_file_path, "w")
        nf.write(initial_text)
        nf.close()
    # Write data to file.
    f = open(list_file_path, "a")
    for line in lines:
        outputline = line+"\n"
        f.write(outputline)
    f.close()
    return


def hash_file(file_path):
    #http://stackoverflow.com/questions/30478972/hashing-files-with-python
    assert(os.path.exists(file_path))
    blocksize = 65536
    with open(file_path, "rb") as f:
        hasher = hashlib.md5()
        buf = f.read(blocksize)
        while len(buf)>0:
            hasher.update(buf)
            buf = f.read(blocksize)
        raw_hash =  hasher.digest()
    md5_base16_hash = base64.b16encode(raw_hash)
    md5_base16_hash_lowercase = md5_base16_hash.lower()
    return md5_base16_hash_lowercase


def save_submissions(requests_session, sid, submission_ids, output_path, download=True, save_json=True, download_link_filepath=None):
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
    # Handle submissions
    for submission_info in results['submissions']:
        # Handle one submission
        submission_id = submission_info['submission_id']

        # Handle submission files
        for submission_file in submission_info['files']:
            #print('submission_file: %s' % (submission_file))
            file_full_url = submission_file['file_url_full']
            original_file_name = submission_file['file_name']
            file_order = submission_file['submission_file_order']
            remote_file_hash = submission_file['full_file_md5']
            if download_link_filepath:
                # Write download link to file
                appendlist(
                    lines = file_full_url,
                    list_file_path = download_link_filepath,
                    initial_text = "# List of download links.\r\n"
                )

            if download:
                # Download file
                download_filepath = os.path.join(output_path, '%s.%s.%s' % (submission_id, file_order, original_file_name))
                logging.info('Now saving file: %s to %s' % (file_full_url, download_filepath))

                assert not os.path.exists(download_filepath)

                file_full_response = fetch(requests_session, file_full_url)
                file_full_data = file_full_response.content

                save_file(
                    file_path = download_filepath,
                    data = file_full_data,
                    force_save=True,
                    allow_fail=False
                )

                local_file_hash = hash_file(download_filepath)
                if local_file_hash != remote_file_hash:
                    raise Exception('Local and remote hashes for this file did not match!\r\n local_file_hash: %s\r\nremote_file_hash: %s' % (local_file_hash, remote_file_hash))

        if save_json:
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


def run_cli():
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
##    parser.add_argument('output_path', help='Output path',
##                    type=str, default='download')
##    parser.add_argument('--make_list', help='write file URLs to a list file',
##                    type=str, default=False)
##    parser.add_argument('--skip_download', help='skip downloading',action="store_true")
    args = parser.parse_args()
    login_username = args.username
    login_password = args.password
    start_num = args.start_num
    end_num = args.end_num
    #output_path = args.output_path
    output_path='download'

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
    logging.info('start_num: %s, end_num: %s ' % (start_num, end_num))

    if start_num == end_num:
        # Handle case of only one submission to save
        nums = [start_num]
        save_submissions(requests_session,
            sid=sid,
            submission_ids=nums,
            output_path=output_path,
            download=True,# TODO add this CLI argument
            save_json=True,# TODO add this CLI argument
            download_link_filepath='download_links.txt'# TODO add this CLI argument
        )

    else:
        # Process range of submissions
        # Break up range into groups of 100
        for low_id in xrange(start_num, end_num, 100):
            # Start with a number x
            high_id = low_id + 99# Add 99 to the number x
            if high_id > end_num:# If the number x+99 is above the maximum, subtract the difference
                high_id -= (high_id - end_num)
            logging.info('low_id: %s, high_id: %s' % (low_id, high_id))
            # Populate groups of 100
            nums = list(range(int(low_id), int(high_id) + 1))# populate the list with numbers from x to x+99
            #print(nums)
            assert(len(nums) <= 100)#
            save_submissions(requests_session,
                sid=sid,
                submission_ids=nums,
                output_path=output_path,
            )
    return


def main():
    try:
        setup_logging(log_file_path=os.path.join('debug','ib_range_dl_log.txt'))
        run_cli()
    except Exception, e:# Log fatal exceptions
        logging.critical("Unhandled exception!")
        logging.exception(e)



if __name__ == '__main__':
    main()
