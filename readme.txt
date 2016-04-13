readme.txt
ib_range_dl.py
Script for downloading inkbunny submissions in bulk

usage: ib_range_dl.py start_num end_num username password output_path

WARNING:
If downloads are interrupted manual repairs of the output will be required.
To do this go into the download folder and delete all files beginning with the submission_id that the failure occured on

Currently the supplied file hashes are not checked at any point.

Output to:
<output_path>/<submission_id>.json
<output_path>/<submission_id>.<file_number>.<file_name>

Licence:
I don't have a fucking clue, if you care you can buy me a legal department or something.