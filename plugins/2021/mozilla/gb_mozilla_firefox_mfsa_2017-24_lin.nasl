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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.24");
  script_cve_id("CVE-2017-7826", "CVE-2017-7827", "CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7831", "CVE-2017-7832", "CVE-2017-7833", "CVE-2017-7834", "CVE-2017-7835", "CVE-2017-7836", "CVE-2017-7837", "CVE-2017-7838", "CVE-2017-7839", "CVE-2017-7840", "CVE-2017-7842");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 10:06:00 +0000 (Wed, 01 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-24) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-24");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-24/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1394530%2C1369561%2C1411458%2C1400003%2C1395138%2C1408412%2C1393840%2C1400763%2C1339259%2C1394265%2C1407740%2C1407751%2C1408005%2C1406398%2C1387799%2C1261175%2C1400554%2C1375146%2C1397811%2C1404636%2C1401804");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1399922%2C1403646%2C1403716%2C1365894%2C1402876%2C1406154%2C1384121%2C1384615%2C1407375%2C1339485%2C1361432%2C1394031%2C1383019%2C1407032%2C1387845%2C1386490");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325923");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1358009");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1366420");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1370497");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1392026");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1397064");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1399540");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1401339");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1402363");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1402896");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1406750");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1408782");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1408990");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1412252");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-7828: Use-after-free of PressShell while restyling layout
A use-after-free vulnerability can occur when flushing and resizing layout because the PressShell object has been freed while still in use. This results in a potentially exploitable crash during these operations.

CVE-2017-7830: Cross-origin URL information leak through Resource Timing API
The Resource Timing API incorrectly revealed navigations in cross-origin iframes. This is a same-origin policy violation and could allow for data theft of URLs loaded by users.

CVE-2017-7831: Information disclosure of exposed properties on JavaScript proxy objects
A vulnerability where the security wrapper does not deny access to some exposed properties using the deprecated exposedProps mechanism on proxy objects. These properties should be explicitly unavailable to proxy objects.

CVE-2017-7832: Domain spoofing through use of dotless 'i' character followed by accent markers
The combined, single character, version of the letter 'i' with any of the potential accents in unicode, such as acute or grave, can be spoofed in the addressbar by the dotless version of 'i' followed by the same accent as a second character with most font sets. This allows for domain spoofing attacks because these combined domain names do not display as punycode.

CVE-2017-7833: Domain spoofing with Arabic and Indic vowel marker characters
Some Arabic and Indic vowel marker characters can be combined with Latin characters in a domain name to eclipse the non-Latin character with some font sets on the addressbar. The non-Latin character will not be visible to most viewers. This allows for domain spoofing attacks because these combined domain names do not display as punycode.

CVE-2017-7834: data: URLs opened in new tabs bypass CSP protections
A data: URL loaded in a new tab did not inherit the Content Security Policy (CSP) of the original page, allowing for bypasses of the policy including the execution of JavaScript. In prior versions when data: documents also inherited the context of the original page this would allow for potential cross-site scripting (XSS) attacks.

CVE-2017-7835: Mixed content blocking incorrectly applies with redirects
Mixed content blocking of insecure (HTTP) sub-resources in a secure (HTTPS) document was not correctly applied for resources that redirect from HTTPS to HTTP, allowing content that should be blocked, such as scripts, to be loaded on a page.

CVE-2017-7836: Pingsender dynamically loads libcurl on Linux and OS X
The 'pingsender' executable used by the Firefox Health Report dynamically loads a system copy of libcurl, which an attacker could replace. This allows for privilege escalation as the replaced libcurl code will run with Firefox's privileges. Note: This attack requires an attacker have local system access and only affects OS X and Linux. Windows systems are not affected.

CVE-2017-7837: SVG loaded as <img> ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 57.");

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

if (version_is_less(version: version, test_version: "57")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "57", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
