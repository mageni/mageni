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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.01");
  script_cve_id("CVE-2019-17015", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17018", "CVE-2019-17019", "CVE-2019-17020", "CVE-2019-17021", "CVE-2019-17022", "CVE-2019-17023", "CVE-2019-17024", "CVE-2019-17025");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 19:15:00 +0000 (Mon, 13 Jan 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1328295%2C1328300%2C1590447%2C1590965%2C1595692%2C1597321%2C1597481");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1507180%2C1595470%2C1598605%2C1601826");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1549394");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1568003");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1590001");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1597645");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1599005");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1599008");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1599181");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1602843");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1603055");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-17015: Memory corruption in parent process during new content process initialization on Windows
During the initialization of a new content process, a pointer offset can be manipulated leading to memory corruption and a potentially exploitable crash in the parent process. Note: this issue only occurs on Windows. Other operating systems are unaffected.

CVE-2019-17016: Bypass of @namespace CSS sanitization during pasting
When pasting a <style> tag from the clipboard into a rich text editor, the CSS sanitizer incorrectly rewrites a @namespace rule. This could allow for injection into certain types of websites resulting in data exfiltration.

CVE-2019-17017: Type Confusion in XPCVariant.cpp
Due to a missing case handling object types, a type confusion vulnerability could occur, resulting in a crash. We presume that with enough effort that it could be exploited to run arbitrary code.

CVE-2019-17018: Windows Keyboard in Private Browsing Mode may retain word suggestions
When in Private Browsing Mode on Windows 10, the Windows keyboard may retain word suggestions to improve the accuracy of the keyboard.

CVE-2019-17019: Python files could be inadvertently executed upon opening a download
When Python was installed on Windows, a python file being served with the MIME type of text/plain could be executed by Python instead of being opened as a text file when the Open option was selected upon download. Note: this issue only occurs on Windows. Other operating systems are unaffected.

CVE-2019-17020: Content Security Policy not applied to XSL stylesheets applied to XML documents
If an XML file is served with a Content Security Policy and the XML file includes an XSL stylesheet, the Content Security Policy will not be applied to the contents of the XSL stylesheet. If the XSL sheet e.g. includes JavaScript, it would bypass any of the restrictions of the Content Security Policy applied to the XML document.

CVE-2019-17021: Heap address disclosure in parent process during content process initialization on Windows
During the initialization of a new content process, a race condition occurs that can allow a content process to disclose heap addresses from the parent process. Note: this issue only occurs on Windows. Other operating systems are unaffected.

CVE-2019-17022: CSS sanitization does not escape HTML tags
When pasting a <style> tag from the clipboard into a rich text editor, the CSS sanitizer does not escape < and > characters. Because the resulting string is pasted directly into the text node of the element this does not result in a direct injection into the webpage, however, if a webpage subsequently copies the node's innerHTML, assigning it to another innerHTML, this would result in an XSS vulnerability. Two WYSIWYG editors were identified with this behavior, more may exist.

CVE-2019-17023: NSS may negotiate TLS 1.2 or below after a TLS 1.3 HelloRetryRequest had been ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 72.");

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

if (version_is_less(version: version, test_version: "72")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "72", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
