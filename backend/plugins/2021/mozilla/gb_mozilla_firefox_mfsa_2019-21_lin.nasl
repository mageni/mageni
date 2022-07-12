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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.21");
  script_cve_id("CVE-2019-11709", "CVE-2019-11710", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11714", "CVE-2019-11715", "CVE-2019-11716", "CVE-2019-11717", "CVE-2019-11718", "CVE-2019-11719", "CVE-2019-11720", "CVE-2019-11721", "CVE-2019-11723", "CVE-2019-11724", "CVE-2019-11725", "CVE-2019-11727", "CVE-2019-11728", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-9811");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-29 14:15:00 +0000 (Mon, 29 Jul 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-21) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-21");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-21/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1547266%2C1540759%2C1548822%2C1550498%2C1515052%2C1539219%2C1547757%2C1550498%2C1533522");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1549768%2C1548611%2C1533842%2C1537692%2C1540590%2C1551907%2C1510345%2C1535482%2C1535848%2C1547472%2C1547760%2C1507696%2C1544180%2C1400563");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1256009");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1408349");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1483510");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1512511");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1515342");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1523741");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1528335");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1528481");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1538007");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1539598");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1539759");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1540541");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1542593");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1543804");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1548306");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1552208");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1552541");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1552632");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1552993");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1555523");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1556230");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1558299");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1563327");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-9811: Sandbox escape via installation of malicious language pack
As part of his winning Pwn2Own entry, Niklas Baumstark demonstrated a sandbox escape by installing a malicious language pack and then opening a browser feature that used the compromised translation.

CVE-2019-11711: Script injection within domain through inner window reuse
When an inner window is reused, it does not consider the use of document.domain for cross-origin protections. If pages on different subdomains ever cooperatively use document.domain, then either page can abuse this to inject script into arbitrary pages on the other subdomain, even those that did not use document.domain to relax their origin security.

CVE-2019-11712: Cross-origin POST requests can be made with NPAPI plugins by following 308 redirects
POST requests made by NPAPI plugins, such as Flash, that receive a status 308 redirect response can bypass CORS requirements. This can allow an attacker to perform Cross-Site Request Forgery (CSRF) attacks.

CVE-2019-11713: Use-after-free with HTTP/2 cached stream
A use-after-free vulnerability can occur in HTTP/2 when a cached HTTP/2 stream is closed while still in use, resulting in a potentially exploitable crash.

CVE-2019-11714: NeckoChild can trigger crash when accessed off of main thread
Necko can access a child on the wrong thread during UDP connections, resulting in a potentially exploitable crash in some instances.

CVE-2019-11729: Empty or malformed p256-ECDH public keys may trigger a segmentation fault
Empty or malformed p256-ECDH public keys may trigger a segmentation fault due values being improperly sanitized before being copied into memory and used.

CVE-2019-11715: HTML parsing error can contribute to content XSS
Due to an error while parsing page content, it is possible for properly sanitized user input to be misinterpreted and lead to XSS hazards on web sites in certain circumstances.

CVE-2019-11716: globalThis not enumerable until accessed
Until explicitly accessed by script, window.globalThis is not enumerable and, as a result, is not visible to code such as Object.getOwnPropertyNames(window). Sites that deploy a sandboxing that depends on enumerating and freezing access to the window object may miss this, allowing their sandboxes to be bypassed.

CVE-2019-11717: Caret character improperly escaped in origins
A vulnerability exists where the caret ('^') character is improperly escaped constructing some URIs due to it being used as a separator, allowing for possible spoofing of origin attributes.

CVE-2019-11718: Activity Stream writes unsanitized content to innerHTML
Activity Stream can display content from sent from the Snippet Service website. This content is written to innerHTML on the Activity Stream page without sanitization, allowing for a potential access to other information available to the Activity Stream, such as browsing history, if the Snipper Service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 68.");

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

if (version_is_less(version: version, test_version: "68")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "68", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
