import itertools
import string
import urllib2
from decimal import *
from distutils.version import LooseVersion

from version import Version


class BaseLibrary(object):
    def __init__(self, versionRanges):
        # For soup/direct maven index:
        self.versions = []
        if not isinstance(versionRanges, basestring):
            for vr in versionRanges:
                self.versions.append(Version(vr))
        else:
            self.versions.append(Version(versionRanges))

        self.versionRanges = versionRanges

import re
import logging
import ConfigParser
from bs4 import BeautifulSoup


class JavaLibrary(BaseLibrary):
    def __init__(self, versionRange, groupId, artifactId):
        getcontext().prec = 2
        self.logger = logging.getLogger(__name__)
        super(JavaLibrary, self).__init__(versionRange)
        self.groupId = groupId
        self.artifactId = artifactId
        self.mavenVersions = set()
        self.affectedMvnSeries = set()
        self.configure()
        self.findAllInSeries()

    def configure(self):
        config = ConfigParser.ConfigParser()
        config.read('victims-db-builder.cfg')
        repos = config.items('java_repos')
        print "repos: %s" % repos
        for repo, url in repos:
            try:
                self.logger.debug('repo: %s' % repo)
                self.indexBaseUrl = url
                self.confirmVersions()
            except:
                self.logger.warn('Processing of repo %s, skipping.' % repo)
                continue


    def confirmVersions(self):
        coords = self.indexBaseUrl + self.groupId.replace('.', '/') + "/" + self.artifactId
        self.logger.debug("coords %s", coords)
        try:
            response = urllib2.urlopen(coords)
        except urllib2.URLError, e:
            if response.code is 404:
                pass
        self.findInMaven(response)

    def findInMaven(self, response):

        # TODO cache page locally for redundency
        mavenPage = response.read()
        soup = BeautifulSoup(mavenPage, 'html.parser')
        links = soup.find_all('a')
        for link in links:
            self.mavenVersions.add(link.get_text().rstrip('/'))


    def findAllInSeries(self):
        verList = []
        regex = ['(,)(\\d+)(\\.)(\\d+)', '(,)(\\d+)']
        for val in self.versionRanges:
            # removing the boundary version if exists
            normalized = None
            boundary = None
            for ind, value in enumerate(regex):
                res = re.compile(value)
                matched = res.search(val)
                if matched is not None and ind == 0:
                    normalized = val.replace(
                        str(matched.group(1) + matched.group(2) + matched.group(3) + matched.group(4)), '')
                    tmp = str(matched.group(1) + matched.group(2) + matched.group(3) + matched.group(4))
                    boundary = tmp.replace(',', '')
                    break
                if matched is not None and ind == 1:
                    normalized = val.replace(str(matched.group(1) + matched.group(2)), '')
                    tmp = str(matched.group(1) + matched.group(2))
                    boundary = tmp.replace(',', '')
                    break
                else:
                    normalized = val

            if '>=' in normalized:
                verList.append(StructureHelper('>=', normalized.replace('>=', ''), boundary))
            if '<=' in normalized:
                verList.append(StructureHelper('<=', normalized.replace('<=', ''), boundary))
            if '<' in normalized and '=' not in normalized:
                verList.append(StructureHelper('<', normalized.replace('<', ''), boundary))
            if '>' in normalized and '=' not in normalized:
                verList.append(StructureHelper('>', normalized.replace('>', ''), boundary))
            if '==' in normalized:
                verList.append(StructureHelper('==', normalized.replace('==', ''), boundary))

        equalsFound = set()
        links = []
        self.findEqualVersions(verList, 0, equalsFound, links)

        finalVersionRanges = []
        if len(links) != 0:
            for each in links:
                versionRange = []
                for ea in each.links:
                    originalVerListValue = verList[ea]
                    versionRange.append(originalVerListValue.symbol + originalVerListValue.version)
                    versionRange.append(originalVerListValue.boundary)
                versionRange.append(each.symbol + each.version)
                finalVersionRanges.append(EqualBaseVersion(versionRange))
        else:
            versionRange = []
            for each in verList:
                versionRange.append(each.symbol + each.version)
                versionRange.append(each.boundary)
                finalVersionRanges.append(EqualBaseVersion(versionRange))

        self.findAllArtifacts(finalVersionRanges)

    # Building the relationship between affected versions in case any version
    # lives between two other versions without
    def findEqualVersions(self, ver, inx, equalsList, links):
        indx = inx
        highIndex = len(ver) - 1
        equalVer = ver[indx]

        try:
            if indx >= highIndex:
                return equalsList
            for index, var in enumerate(ver):
                if index <= highIndex and index is indx:
                    continue
                if isinstance(var, StructureHelper) and isinstance(equalVer, StructureHelper):
                    # Striping the third precision to compare the base versions
                    if self.normalizeText(equalVer.version) == self.normalizeText(var.version):
                        if len(links) != 0:
                            for ix, value in enumerate(links):
                                if self.normalizeText(equalVer.version) == self.normalizeText(value.version):
                                    if not any(eq == indx for eq in value.links):
                                        structureObject = links[ix]
                                        if isinstance(structureObject, StructureHelper):
                                            structureObject.addToLinks(index)
                                elif ix == len(links) - 1:
                                    self.addStructureToLinks(equalVer, index, links)
                                else:
                                    continue
                        else:
                            self.addStructureToLinks(equalVer, index, links)

            self.findEqualVersions(ver, indx + 1, equalsList, links)
        except Exception as e:
            self.logger.error("Error occurred while building affected versions relationship", str(e))

    def addStructureToLinks(self, equalVer, index, links):
        if equalVer.symbol == '>=':
            c = StructureHelper('>=', equalVer.version, equalVer.boundary)
            c.addToLinks(index)
            links.append(c)
        if equalVer.symbol == '<=':
            c = StructureHelper('<=', equalVer.version, equalVer.boundary)
            c.addToLinks(index)
            links.append(c)
        if equalVer.symbol == '==':
            c = StructureHelper('==', equalVer.version, equalVer.boundary)
            c.addToLinks(index)
            links.append(c)
        if equalVer.symbol == '>':
            c = StructureHelper('>', equalVer.version, equalVer.boundary)
            c.addToLinks(index)
            links.append(c)
        if equalVer.symbol == '<':
            c = StructureHelper('<', equalVer.version, equalVer.boundary)
            c.addToLinks(index)
            links.append(c)

    def normalizeText(self, text):
        baseVersion = ''
        for indx, char in enumerate(text):
            if indx <= 2:
                baseVersion += str(char)
        return baseVersion

    def findAllArtifacts(self, translatedVersions):

        if len(self.mavenVersions) == 0:
            self.logger.warn('acquired maven artifacts is empty')

        if len(translatedVersions) != 0:
            for version in translatedVersions:
                for mvn in self.mavenVersions:
                    mavenSuffix = []
                    found = False
                    comparableVersion = ''
                    for char in mvn:
                        if found is not True:
                            if char == '.':
                                comparableVersion += char
                                continue
                            try:
                                integerChar = int(char)
                                comparableVersion += str(integerChar)
                            except ValueError:
                                mavenSuffix.append(char)
                                found = True
                        else:
                            mavenSuffix.append(char)
                    attachedSuffix = ''

                    for su in mavenSuffix:
                        attachedSuffix += str(su)

                    # Case where boundary version is specified as one digit i.e 9
                    if len(version.boundary) == 1 and version.boundary == comparableVersion[:1]:
                        self.compareVersions(attachedSuffix, comparableVersion, version)

                    # Case where boundary version is specified with decimal point i.e 9.2
                    if len(version.boundary) == 3 and version.boundary == self.normalizeText(comparableVersion):
                        # Case where affected versions are between to versions
                        if version.greaterThanOrEqualTo is not None and version.lessThanOrEqualTo is not None:
                            if (LooseVersion(comparableVersion) == LooseVersion(version.greaterThanOrEqualTo.replace('<=', '')) or
                                    (LooseVersion(comparableVersion) < LooseVersion(version.greaterThanOrEqualTo.replace('<=', ''))
                                     and LooseVersion(comparableVersion) > LooseVersion(version.lessThanOrEqualTo.replace('>=', '')))) and \
                                (LooseVersion(comparableVersion) == LooseVersion(version.lessThanOrEqualTo.replace('>=', '')) or
                                     (LooseVersion(comparableVersion) > LooseVersion(version.lessThanOrEqualTo.replace('>=', '')) and
                                      LooseVersion(comparableVersion) < LooseVersion(version.greaterThanOrEqualTo.replace('<=', '')))):
                                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)
                        self.compareVersions(attachedSuffix, comparableVersion, version)

        else:
            self.logger.warn('either affected version range is unavailable')

        for version in self.affectedMvnSeries:
            self.logger.debug(version.version   )

    def populatedAffectedLibraries(self, attachedSuffix, comparableVersion):
        self.affectedMvnSeries.add(
            AffectedJavaLibrary(self.groupId, self.artifactId, str(comparableVersion + attachedSuffix)))

    def compareVersions(self, attachedSuffix, comparableVersion, version):
        if version.equal is not None:
            if LooseVersion(version.equal.replace('==', '')) == LooseVersion(comparableVersion):
                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)
        if version.greaterThanOrEqualTo is not None and version.lessThanOrEqualTo is None:
            if LooseVersion(comparableVersion) == LooseVersion(version.greaterThanOrEqualTo.replace('<=', '')) or \
                            LooseVersion(comparableVersion) < LooseVersion(
                        version.greaterThanOrEqualTo.replace('<=', '')):
                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)
        if version.lessThanOrEqualTo is not None and version.greaterThanOrEqualTo is None:
            if LooseVersion(comparableVersion) == LooseVersion(version.lessThanOrEqualTo.replace('>=', '')) or \
                            LooseVersion(comparableVersion) > LooseVersion(version.lessThanOrEqualTo.replace('>=', '')):
                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)
        if version.greaterThan is not None:
            if LooseVersion(comparableVersion) < LooseVersion(version.greaterThan.replace('<', '')):
                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)
        if version.lessThan is not None:
            if LooseVersion(comparableVersion) > LooseVersion(version.lessThan.replace('>', '')):
                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)

        # Case where an affected version is between two other versions
        if version.lessThan is not None and version.greaterThan is not None:
            if LooseVersion(comparableVersion) < LooseVersion(version.greaterThan.replace('<', '')) and \
                            LooseVersion(comparableVersion) > LooseVersion(version.lessThan.replace('>', '')):
                self.populatedAffectedLibraries(attachedSuffix, comparableVersion)


class AffectedJavaLibrary:
    def __init__(self, groupId, artifactId, version):
        self.groupId = groupId
        self.artifactId = artifactId
        self.version = version


class EqualBaseVersion:
    def __init__(self, *args):
        self.equal = None
        self.lessThanOrEqualTo = None
        self.greaterThanOrEqualTo = None
        self.lessThan = None
        self.greaterThan = None
        self.boundary = None

        for arg in args:
            for each in arg:
                if '==' in each:
                    self.equal = each
                elif '>=' in each:
                    self.lessThanOrEqualTo = each
                elif '<=' in each:
                    self.greaterThanOrEqualTo = each
                elif '>' in each and '=' not in each:
                    self.lessThan = each
                elif '<' in each and '=' not in each:
                    self.greaterThan = each
                else:
                    self.boundary = each


class StructureHelper:
    def __init__(self, symbol, version, boundary):
        self.symbol = symbol
        self.version = version
        self.boundary = boundary
        self.links = set()

    def addToLinks(self, link):
        self.links.add(link)