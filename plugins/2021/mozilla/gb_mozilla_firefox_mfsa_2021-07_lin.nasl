# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.07");
  script_cve_id("CVE-2020-26954", "CVE-2021-23968", "CVE-2021-23969", "CVE-2021-23970", "CVE-2021-23971", "CVE-2021-23972", "CVE-2021-23973", "CVE-2021-23974", "CVE-2021-23975", "CVE-2021-23976", "CVE-2021-23977", "CVE-2021-23978", "CVE-2021-23979");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 00:15:00 +0000 (Sat, 01 May 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-07) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-07");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-07/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1528997%2C1683627");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1663222%2C1666607%2C1672120%2C1678463%2C1678927%2C1679560%2C1681297%2C1681684%2C1683490%2C1684377%2C1684902");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=786797%2C1682928%2C1687391%2C1687597");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1542194");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1678545");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1681724");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1683536");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1684627");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1684761");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1685145");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1687342");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1690976");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-23969: Content Security Policy violation report could have contained the destination of a redirect
As specified in the W3C Content Security Policy draft, when creating a violation report, 'User agents need to ensure that the source file is the URL requested by the page, pre-redirects. If that's not possible, user agents need to strip the URL down to an origin to avoid unintentional leakage.' Under certain types of redirects, Firefox incorrectly set the source file to be the destination of the redirects. This was fixed to be the redirect destination's origin.

CVE-2021-23970: Multithreaded WASM triggered assertions validating separation of script domains
Context-specific code was included in a shared jump table, resulting in assertions being triggered in multithreaded wasm code.

CVE-2021-23968: Content Security Policy violation report could have contained the destination of a redirect
If Content Security Policy blocked frame navigation, the full destination of a redirect served in the frame was reported in the violation report, as opposed to the original frame URI. This could be used to leak sensitive information contained in such URIs.

CVE-2021-23974: noscript elements could have led to an HTML Sanitizer bypass
The DOMParser API did not properly process <noscript> elements for escaping. This could be used as an mXSS vector to bypass an HTML Sanitizer.

CVE-2021-23971: A website's Referrer-Policy could have been be overridden, potentially resulting in the full URL being sent as a Referrer
When processing a redirect with a conflicting Referrer-Policy, Firefox would have adopted the redirect's Referrer-Policy. This would have potentially resulted in more information than intended by the original origin being provided to the destination of the redirect.

CVE-2021-23976: Local spoofing of web manifests for arbitrary pages in Firefox for Android
When accepting a malicious intent from other installed apps, Firefox for Android accepted manifests from arbitrary file paths and allowed declaring webapp manifests for other origins. This could be used to gain fullscreen access for UI spoofing and could also lead to cross-origin attacks on targeted websites.Note: This issue is a different issue from CVE-2020-26954 and only affected Firefox for Android. Other operating systems are unaffected.

CVE-2021-23977: Malicious application could read sensitive data from Firefox for Android's application directories
Firefox for Android suffered from a time-of-check-time-of-use vulnerability that allowed a malicious application to read sensitive data from application directories.Note: This issue is only affected Firefox for Android. Other operating systems are unaffected.

CVE-2021-23972: HTTP Auth phishing warning was omitted when a redirect is cached
One phishing tactic on the web is to provide a link with HTTP Auth. For example https://www.phishingtarget.com@evil.com. To mitigate ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 86.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "86")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "86", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
