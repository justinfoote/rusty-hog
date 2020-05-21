#!/usr/bin/env python

# This is a simple script meant to filter the results from choctaw-hog using a list of
# allowed words. It accepts a single optional parameter -- the filename of the json
# report to filter.  If not provided, it looks for a file called 'output.json'. It
# creates a new file to hold the filtered report, given the name of the input file
# prepended with 'filtered_'.

import csv
import sys
import json

fpwords = ['foo',
           'bar',
           'example',
           'test',
           'host.com',
           'LicenseEditMaskedEdit',
           'user:pass',
           'git@github',
           'TRAFFIC_INSIGHTS',
           'GithubComGoogleSubcommands',
           'DO_NOT_USE',
           'account', # FILTERS ALL ACCOUNT ID FINDINGS!
           'DO_NOT_PASS_THIS',
           '0000000000',
           'local_development',
           'bootstrap',
           'local_production',
           'username@hostname',
           '1234567890',
           '0123456789',
           'metadata-injection',
           'kubernetes-static',
           'fitzgen@github.com',
           'user@domain.com',
           'admin:admin123',
           '$gh_token:x-oauth-basic',
           'templates',
           'you-must-create',
           'username:password',
           'Agent.Core.dll',
           'code.highcharts.com',
           'OS_DEPENDENT_NETWORK',
           'LicenseKeyEditEdit',
           '@bitbucket.org/',
           '123456789',
           'abcdefghij',
           'XXXXXXXXXX',
           'YOUR_GITLAB_TOKEN',
           'rpm_site_local_dev__secret',
           'secret-key-authenticated-encryption-secretbox'
           ]


def fpfilter(entry):
    return not any([word.lower() in string.lower()
            for word in fpwords
            for string in entry['stringsFound']])


def filter_file(filename):
    with open(filename) as infile:
        positives = json.load(infile)
        with open('filtered_%s' % filename, 'w') as outfile:
          json.dump(list(filter(fpfilter, positives)), outfile)

if __name__ == '__main__':
  filename = sys.argv[1] if len(sys.argv) > 1 else 'output.json'
  filter_file(filename)
