from sys import argv
from os import path
from git import Repo, remote, exc, diff
import ConfigParser

import processor

config = ConfigParser.SafeConfigParser()
config.read('victims-db-builder.cfg')
repoUrl = config.get('cve_db', 'repo')
filePath = config.get('cve_db', 'path')
javaPath = config.get('cve_db', 'javaPath')

def main():
    try:
        repo = Repo(filePath)
    except exc.InvalidGitRepositoryError, e:
        repo = Repo.clone_from(repoUrl, filePath)
        #TODO fix submit to work with victims-upload
        processor.findYamlFiles(repo.working_tree_dir + '/' + javaPath, "", "")
    else:
        doUpdate(repo)


def doUpdate(repo):
    currentCommit = repo.head.commit
    repo.remotes.origin.pull()
    diff = currentCommit.diff()
    for d in diff.iter_change_type('A'):
        if d.new_file:
            if javaPath in d.b_path:
                processor.processReport(d.b_path, "", "")


if __name__ == '__main__':
    main()
