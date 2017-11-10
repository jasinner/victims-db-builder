from sys import argv
from os import path
from git import Repo, remote, exc
import ConfigParser

import processor

config = ConfigParser.SafeConfigParser()
config.read('victims-db-builder.cfg')
repoUrl = config.get('cve_db', 'repo')
filePath = config.get('cve_db', 'path')
javaPath = config.get('cve_db', 'javaPath')

def main(argv):
    if len(argv) != 2:
        print """Usage: python repo.py <victims-upload-url>"""
    else:
        script, uploadUrl = argv
        #Check if we already have a clone
        try:
            repo = Repo(filePath)
        except exc.InvalidGitRepositoryError, e:
            repo = Repo.clone_from(repoUrl, filePath)
            #TODO fix submit to work with victims-upload
            processor.findYamlFiles(repo.working_tree_dir + '/' + javaPath, "", "")
        else:
            doUpdate()


def doUpdate():
    print 'Do update called'


if __name__ == '__main__':
    main(argv)