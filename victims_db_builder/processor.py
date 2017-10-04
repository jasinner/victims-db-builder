import vulnerability
import upload
from os import walk, path, remove
from sys import argv
import logging
import logging.config
import requests
from ConfigParser import ConfigParser

logging.config.fileConfig('logging.cfg')
logger = logging.getLogger('victimsDBBuilder')
config = ConfigParser()
config.read('victims-db-builder.cfg')

def main(argv):
    if len(argv) != 4:
        print """Usage: python processor.py <dir|file.yaml>
            <victims-api-username> <victims-api-password>"""
    else:
        script, target, username, password = argv
        if target.endswith('.yaml'):
            processReport(target, username, password)
        else:
            findYamlFiles(target, username, password)


def findYamlFiles(baseDir, username, password):
    for root, dirs, files in walk(baseDir):
        for file in files:
            if file.endswith('.yaml'):
                yamlFile = path.join(root, file)
                logger.info("processing: %s", yamlFile)
                processReport(yamlFile, username, password)

def processReport(yamlFile, username, password):
    vuln = vulnerability.construct_yaml(yamlFile)
    for library in vuln.libraries:
        path = buildMavenPath(library)
        logger.info("Downloading file from: %s" % path)
        filename = download_file(path)
        upload.uploadArchive(username, password, filename, vuln.cve)
        remove(filename)

def download_file(url):
    local_filename = url.split('/')[-1]
    dir = config.get('local', 'download_dir')
    local_filename = "%s/%s" % (dir, local_filename)
    # NOTE the stream=True parameter
    r = requests.get(url, stream=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                #f.flush() commented by recommendation from J.F.Sebastian
    return local_filename

def buildMavenPath(library):
    path = library.groupId.replace(".", "/")
    path += "/" + library.artifactId
    path += "/" + library.version
    path += "/" + library.artifactId
    path += "-" + library.version
    path += ".jar"
    path = library.repo + path
    return path

if __name__ == '__main__':
    main(argv)
