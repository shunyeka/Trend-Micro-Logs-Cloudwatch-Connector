#!/usr/bin/env python3
# Here we can list the vulnerabilities from smart check

import argparse
import os
import sys
import json
from smartcheck import Smartcheck

ALL_SEVERITIES = [
    'defcon1',
    'critical',
    'high',
    'medium',
    'low',
    'negligible',
    'unknown',
]


def get_vector(vector, vulnerability):
    """Get a vector out of the CVSS definition (if present) for a vulnerability."""
    vectors = []

    # Some sources have metadata as { metadata: NVD: CVSSv3: Vectors: "..." }
    # and others have { metadata: CVSSv2: "..." }
    if 'metadata' in vulnerability:
        if 'NVD' in vulnerability['metadata']:
            vectors = vulnerability['metadata']['NVD'].get(
                'CVSSv3', {}).get('Vectors', '').split('/')
            if len(vectors) == 1:
                vectors = vulnerability['metadata']['NVD'].get(
                    'CVSSv2', {}).get('Vectors', '').split('/')
        else:
            cvssV2 = vulnerability['metadata'].get('CVSSv2', None)
            if isinstance(cvssV2, str):
                vectors = cvssV2.split('/')
                # The first element is the score, which we're not using here
                vectors.pop(0)

    found = list(filter(lambda x: vector in x, vectors))
    if found:
        return found[0]
    return None


def sev_list(min_level):
    return ALL_SEVERITIES[:ALL_SEVERITIES.index(min_level) + 1]


def get_analysis(smartcheck_host, smartcheck_user, smartcheck_password,image,min_severity='high', show_fixed=False,
                 show_overridden=False,
                 insecure_skip_tls_verify=True):
    result = {
        "malware": {
            "name": "Malware found in image",
            "items": []
        },
        "content_risk": {
            "name": "Content secret risk found",
            "items": []
        },
        "compliance_check_failures": {
            "name": "Failed Compliance checklist for image",
            "items": []
        },
        "compliance_checklist": {
            "name": "Display Checklist_compliance of Trend Micro",
            "pci-dss": {
                "name": "Trend Micro PCI-DSS v3 Docker Compliance",
                "items": []
            },
            "nist800190": {
                "name": "Trend Micro NIST 800-190 Docker Compliance",
                "items": []
            },
            "hipaa": {
                "name": "Trend Micro HIPAA Docker Compliance",
                "items": []
            }

        },
        "vulnerable_package": {
            "name": "vulnerable_package list table",
            "items": []

        }
    }

    if smartcheck_host is None:
        print('smartcheck-host is required', file=sys.stderr)
        sys.exit(1)

    if smartcheck_user is None:
        print('smartcheck_user is required', file=sys.stderr)
        sys.exit(1)

    if smartcheck_password is None:
        print('smartcheck_password is required', file=sys.stderr)
        sys.exit(1)

    if image is None:
        print('scan image is required', file=sys.stderr)
        sys.exit(1)

    try:
        notable_list = sev_list(min_severity)
    except ValueError:
        print('unrecognized severity')
        sys.exit(1)

    with Smartcheck(
            base=smartcheck_host,
            verify=(not insecure_skip_tls_verify),
            user=smartcheck_user,
            password=smartcheck_password
    ) as session:
        # list_scans(image) will return a generator that will give us all of the
        # scans for that image if we ask for them. We're only going to ask for one
        # because we only care about the last scan result.

        for scan in session.list_scans(image, limit=1):

            # We only want to print out the header if there are notable vulnerabilities,
            # which we won't know until later.
            first = True

            # list_vulnerable_packages(scan) will return a generator that will give
            # us all of the vulnerable packages. Each package will have a list of
            # vulnerabilities.

            for package_malware in session.list_malware(scan):
                result['malware']['items'].append({
                    "name": package_malware['icrc']['name'],
                    "infected_file": package_malware['filename']
                })
            for package_content in session.list_content_findings(scan):
                result['content_risk']['items'].append({
                    "severity": package_content['severity'],
                    "severity content found in image": package_content['metadata']['SubCategory1'],
                    "found at": package_content['filename'],
                })

            for package_checklist in session.list_checklist_findings(scan):
                if package_checklist['profile']['title'] == "Trend Micro PCI-DSS v3 Docker Compliance":
                    result['compliance_checklist']['pci-dss']["items"].append({
                        "result_title": package_checklist['result']['title'],
                        "result": package_checklist['result']['result']})

            for package_checklist in session.list_checklist_findings(scan):
                if package_checklist['profile']['title'] == "Trend Micro NIST 800-190 Docker Compliance":
                    result['compliance_checklist']['nist800190']['items'].append({
                        "result_title": package_checklist['result']['title'],
                        "result": package_checklist['result']['result']})
            for package_checklist in session.list_checklist_findings(scan):
                if package_checklist['profile']['title'] == "Trend Micro HIPAA Docker Compliance":
                    result['compliance_checklist']['hipaa']['items'].append({
                        "result_title": package_checklist['result']['title'],
                        "result": package_checklist['result']['result']})

            for package in session.list_vulnerable_packages(scan):
                name = package.get('name', "-unknown-")

                # Now let's go through the vulnerabilities.
                for vulnerability in package['vulnerabilities']:
                    severity = vulnerability['severity']

                    # Skip low-severity vulnerabilities unless the user wants them
                    if not severity in notable_list:
                        continue

                    # Don't show vulnerabilities that have been fixed
                    if 'fixed' in vulnerability:
                        if not show_fixed:
                            continue

                    # Only show overridden vulnerabilities if the user has asked for them
                    if 'override' in vulnerability:
                        if not show_overridden:
                            continue

                    description = (" ", vulnerability['description'])['description' in vulnerability]
                    cve = vulnerability['name']
                    link = vulnerability['link']
                    vector = get_vector('AV:', vulnerability)
                    if vector is not None:
                        # Some sources encode the full vector (for example AV:NETWORK),
                        # others use the abbreviation (AV:N). We'll abbreviate for
                        # consistency.
                        vector = vector[:4]
                    else:
                        vector = '?'

                    # We have a notable vulnerability that we want to display, if
                    # it's the first one we'll add a pretty header
                    if first:
                        first = False

                    result['vulnerable_package']['items'].append({
                        "name": name,
                        "description": vulnerability['description'],
                        "severity": severity,
                        "venerability": cve,
                        "vector": vector,
                        "link": link
                    })

            break
    return result
