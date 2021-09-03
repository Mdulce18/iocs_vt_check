# Open csv and make and array with all iocs
# check ioc type sha1 or md5
# take ioc an chekc to VT API for Mcafee and Sentinell One detection
# show in screen something like "hash"\nMcafee=OK \nSentinellOne=OK | SentineLlOne=NO_MATCH add no match to an array
# create a file printing two arrays one for sha1-Sentinell and other for md5-mcafee

import csv
import logging
import config
from time import ctime

# use %kill_emdedded and exit with embed() to debug OR continue with breakpoint()
# from IPython import embed
from virus_total_apis import PublicApi  # pip install virustotal-api

# Create logger
logger = logging.getLogger('ioc_check')
# Create handler
logger_handler = logging.StreamHandler()
# Create formater and add to logger
logger_format = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger_handler.setFormatter(logger_format)
# Add handler to the logger
logger.addHandler(logger_handler)

api = PublicApi(config.vt_apikey)


def ioc_list_creation(csvfile):
    ioc_list = []
    try:
        with open(csvfile, newline='') as f:
            # pass the file object to reader() to get the reader object
            reader = csv.reader(f)
            # append a list for each raw,
            ioc_list = list(reader)
    except:
        logger.error('Error loading csv file')
        return None
    return ioc_list  # return nested list


def check_hash_type(hash_list):
    sha1_hashes = []
    md5_hashes = []
    if hash_list is None or hash_list == [[]]:
        logger.error('Cannot Continue: Empty list to hash check')
        return None, None
    else:
        for raw in hash_list:
            for hashes in raw:
                hash_length = len(hashes)
                if hash_length == 40:
                    sha1_hashes.append(hashes)
                if hash_length == 32:
                    md5_hashes.append(hashes)
        # before return check for duplicates and lower case all
        sha1_hashes_format = [hashes.lower() for hashes in sha1_hashes]
        md5_hashes_format = [hashes.lower() for hashes in md5_hashes]
        sha1_hashes_final = list(dict.fromkeys(sha1_hashes_format))
        md5_hashes_final = list(dict.fromkeys(md5_hashes_format))
        return sha1_hashes_final, md5_hashes_final

# Check against VT


# chech vt conection three times
def check_vt_conecction():
    for retry_times in range(0, 3):
        test = api.get_file_report(
            '6171000983cf3896d167e0d8aa9b94ba')
        try:
            if test["response_code"] == 200:
                return True
            if test["response_code"] == 204:
                error_code = test["response_code"]
                logger.error(
                    f'Request rate limit exceeded. Response {error_code}')
        except KeyError:
            logger.error('Connection to VT failed. Retrying in 20 sec')
    return None


def check_against_vt(ioc_list, av_to_check):
    connection_result = check_vt_conecction()
    if ioc_list is None:
        logger.error(
            f'Cannot Continue: Empty {ioc_list} list to check against VT')
        return None
    if connection_result is None:
        logger.error(f'Cannot Continue: Connection to VT failed')
        return None
    else:
        detected_hashes = ['Detected Hashes']
        undetected_hashes = ['Undetected Hashes']
        non_existent_hashes = ['Non-Existent in VT hashes']
        false_positive_hashes = ['False Positive Hashes']
        for ioc in ioc_list:
            response = api.get_file_report(ioc)
            # breakpoint()
            if response["response_code"] == 200:
                # Move trought API response
                if response['results']['response_code'] == 0:
                    print(f'No results for {ioc}. File doesnt exist in VT')
                    non_existent_hashes.append(ioc)
                    continue
                else:
                    positive = response['results']['positives']
                    if positive > 0:
                        try:
                            av_result = response['results']['scans'][av_to_check]['detected']
                            continue
                        except KeyError:
                            logger.error(f'Timeout for {av_to_check} detection')
                            undetected_hashes.append(ioc)
                            print(f'AV detected: {ioc} False')
                            continue
                        if av_result is True:
                            detected_hashes.append(ioc)
                            print(f'AV detected: {ioc} OK')
                            continue
                        else:
                            undetected_hashes.append(ioc)
                            print(f'AV detected: {ioc} False')
                            continue
                    else:
                        false_positive_hashes.append(ioc)
                        print(f'AV Undetected: {ioc} False Positive by Vendor')
                        continue
            if response["response_code"] == 204:
                error_code = response["response_code"]
                logger.error(
                    f'Request rate limit exceeded in list. Response {error_code}')
            else:
                logger.error(f'Error checking {ioc}.')
                undetected_hashes.append(ioc)
        list_of_detection = [detected_hashes, undetected_hashes,
                             non_existent_hashes, false_positive_hashes]
        return list_of_detection


def write_hashes_in_csv(list_of_av_detection, file_name):
    try:
        with open(file_name, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(list_of_av_detection)
        return True
    except:
        logger.error(f'Error creating {file_name} file')


def file_output_name():
    time = ctime()
    md5_file_name = f'md5_av_detection-{time}.csv'
    sha1_file_name = f'sha1_av_detection-{time}.csv'
    return md5_file_name, sha1_file_name


def main():
    md5_file_name, sha1_file_name = file_output_name()
    hash_list = ioc_list_creation(config.csv_read_file)
    sha1_list, md5_list = check_hash_type(hash_list)
    # breakpoint()
    md5_av_hashes = check_against_vt(md5_list, config.av_options[0])
    sha1_av_hashes = check_against_vt(sha1_list, config.av_options[1])
    write_hashes_in_csv(md5_av_hashes, f'{md5_file_name}')
    write_hashes_in_csv(sha1_av_hashes, f'{sha1_file_name}')


if __name__ == "__main__":
    main()
