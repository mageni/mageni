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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.34");
  script_cve_id("CVE-2018-6156", "CVE-2019-11757", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-11765", "CVE-2019-15903", "CVE-2019-17000", "CVE-2019-17001", "CVE-2019-17002", "CVE-2020-12412");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 15:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-34) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-34");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-34/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1558522%2C1577061%2C1548044%2C1571223%2C1573048%2C1578933%2C1575217%2C1583684%2C1586845%2C1581950%2C1583463%2C1586599");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1441468");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1480088");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1528587");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1561056");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1561502");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1562582");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1577107");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1577719");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1577953");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1582857");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1584216");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1584907");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1587976");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-6156: Heap buffer overflow in FEC processing in WebRTC
Incorrect derivation of a packet length in WebRTC caused heap corruption via a crafted video file. This resulted in a potentially exploitable crash.

CVE-2019-15903: Heap overflow in expat library in XML_GetCurrentLineNumber
In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to document parsing too early. A subsequent call to XML_GetCurrentLineNumber or XML_GetCurrentColumnNumber then resulted in a heap-based buffer over-read.

CVE-2019-11757: Use-after-free when creating index updates in IndexedDB
When storing a value in IndexedDB, the value's prototype chain is followed and it was possible to retain a reference to a locale, delete it, and subsequently reference it. This resulted in a use-after-free and a potentially exploitable crash.

CVE-2020-12412: Address bar spoof using history navigation and blocked ports
By navigating a tab using the history API, an attacker could cause the address bar to display the incorrect domain (with the https:// scheme, a blocked port number such as '1', and without a lock icon) while controlling the page contents.

CVE-2019-11759: Stack buffer overflow in HKDF output
An attacker could have caused 4 bytes of HMAC output to be written past the end of a buffer stored on the stack. This could be used by an attacker to execute arbitrary code or more likely lead to a crash.

CVE-2019-11760: Stack buffer overflow in WebRTC networking
A fixed-size stack buffer could overflow in nrappkit when doing WebRTC signaling. This resulted in a potentially exploitable crash in some instances.

CVE-2019-11761: Unintended access to a privileged JSONView object
By using a form with a data URI it was possible to gain access to the privileged JSONView object that had been cloned into content. Impact from exposing this object appears to be minimal, however it was a bypass of existing defense in depth mechanisms.

CVE-2019-11762: document.domain-based origin isolation has same-origin-property violation
If two same-origin documents set document.domain differently to become cross-origin, it was possible for them to call arbitrary DOM methods/getters/setters on the now-cross-origin window.

CVE-2019-11763: Incorrect HTML parsing results in XSS bypass technique
Failure to correctly handle null bytes when processing HTML entities resulted in Firefox incorrectly parsing these entities. This could have led to HTML comment text being treated as HTML which could have led to XSS in a web application under certain conditions. It could have also led to HTML entities being masked from filters, enabling the use of entities to mask the actual characters of interest from filters.

CVE-2019-11765: Incorrect permissions could be granted to a website
A compromised content process could send a message to the parent process that would cause the 'Click to Play' permission ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 70.");

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

if (version_is_less(version: version, test_version: "70")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "70", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
