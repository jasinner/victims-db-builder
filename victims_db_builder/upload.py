import requests
from hmac import HMAC
from datetime import datetime
#from hashlib import md5, sha512
import logging
import logging.config
import ConfigParser

config = ConfigParser.SafeConfigParser()
config.read('victims-db-builder.cfg')
hostname = config.get('victims_api', 'hostname')
port = config.get('victims_api', 'port')
protocol = config.get('victims_api', 'protocol')
server = "{0}://{1}:{2}".format(protocol, hostname, port)


logging.config.fileConfig('logging.cfg')
logger = logging.getLogger('victimsDBBuilder')


def uploadArchive(username, password, filename, cve):
    logger.info("uploading file: %s" % filename)
    path = getPath(cve)
    url = server + path
    with open(filename, 'rb') as archive:
        files = { 'archive': archive }
        response = requests.post(url,
            files=files,
            auth = (username, password)
            #verify='COMODO_DV_SHA-256_bundle.crt'
       )
        logger.info(response.text)

def submit(username, password, gid, aid, vid, cves):
    path = getPath(gid, aid, vid, cves)
    url = server + path
    logger.info("Submitting to path: %s" % url)
    response = requests.post(url,
        auth = (username, password),
        verify = 'COMODO_DV_SHA-256_bundle.crt'
    )
    logger.info(response.text)

def getPath(cve):
    return "/upload/%s" % (cve)
