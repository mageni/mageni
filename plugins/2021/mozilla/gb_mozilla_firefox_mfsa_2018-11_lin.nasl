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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.11");
  script_cve_id("CVE-2018-5150", "CVE-2018-5151", "CVE-2018-5152", "CVE-2018-5153", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5160", "CVE-2018-5163", "CVE-2018-5164", "CVE-2018-5165", "CVE-2018-5166", "CVE-2018-5167", "CVE-2018-5168", "CVE-2018-5169", "CVE-2018-5172", "CVE-2018-5173", "CVE-2018-5174", "CVE-2018-5175", "CVE-2018-5176", "CVE-2018-5177", "CVE-2018-5179", "CVE-2018-5180", "CVE-2018-5181", "CVE-2018-5182");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 12:44:00 +0000 (Wed, 13 Mar 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-11) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-11");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-11/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1388020%2C1433609%2C1409440%2C1448705%2C1451376%2C1452202%2C1444668%2C1393367%2C1411415%2C1426129");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1445234%2C1449530%2C1437455%2C1447989%2C1438827%2C1436983%2C1435036%2C1440465%2C1439723%2C1448771%2C1453653%2C1454359%2C1432323%2C1454126%2C1436759%2C1439655%2C1448612%2C1449358%2C1367727%2C1452417");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1319157");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1415644");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1416045");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1424107");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1426353");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1427289");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1432358");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1432846");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1435908");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1436117");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1436482");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1436809");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1437325");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1438025");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1441941");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1442840");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1443092");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1444086");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1447080");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1447969");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1448774");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1449548");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1449898");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1451452");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1451908");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1452075");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-5154: Use-after-free with SVG animations and clip paths
A use-after-free vulnerability can occur while enumerating attributes during SVG animations with clip paths. This results in a potentially exploitable crash.

CVE-2018-5155: Use-after-free with SVG animations and text paths
A use-after-free vulnerability can occur while adjusting layout during SVG animations with text paths. This results in a potentially exploitable crash.

CVE-2018-5157: Same-origin bypass of PDF Viewer to view protected PDF files
Same-origin protections for the PDF viewer can be bypassed, allowing a malicious site to intercept messages meant for the viewer. This could allow the site to retrieve PDF files restricted to viewing by an authenticated user on a third-party website.

CVE-2018-5158: Malicious PDF can inject JavaScript into PDF Viewer
The PDF viewer does not sufficiently sanitize PostScript calculator functions, allowing malicious JavaScript to be injected through a crafted PDF file. This JavaScript can then be run with the permissions of the PDF viewer by its worker.

CVE-2018-5159: Integer overflow and out-of-bounds write in Skia
An integer overflow can occur in the Skia library due to 32-bit integer use in an array without integer overflow checks, resulting in possible out-of-bounds writes. This could lead to a potentially exploitable crash triggerable by web content.

CVE-2018-5160: Uninitialized memory use by WebRTC encoder
WebRTC can use a WrappedI420Buffer pixel buffer but the owning image object can be freed while it is still in use. This can result in the WebRTC encoder using uninitialized memory, leading to a potentially exploitable crash.

CVE-2018-5152: WebExtensions information leak through webRequest API
WebExtensions with the appropriate permissions can attach content scripts to Mozilla sites such as accounts.firefox.com and listen to network traffic to the site through the webRequest API. For example, this allows for the interception of username and an encrypted password during login to Firefox Accounts. This issue does not expose synchronization traffic directly and is limited to the process of user login to the website and the data displayed to the user once logged in.

CVE-2018-5153: Out-of-bounds read in mixed content websocket messages
If websocket data is sent with mixed text and binary in a single message, the binary data can be corrupted. This can result in an out-of-bounds read with the read memory sent to the originating server in response.

CVE-2018-5163: Replacing cached data in JavaScript Start-up Bytecode Cache
If a malicious attacker has used another vulnerability to gain full control over a content process, they may be able to replace the alternate data resources stored in the JavaScript Start-up Bytecode Cache (JSBC) for other JavaScript code. If the parent process then runs this replaced code, the executed script would be run with the parent ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 60.");

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

if (version_is_less(version: version, test_version: "60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "60", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
