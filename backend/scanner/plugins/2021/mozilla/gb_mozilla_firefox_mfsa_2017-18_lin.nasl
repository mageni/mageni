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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.18");
  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7780", "CVE-2017-7781", "CVE-2017-7782", "CVE-2017-7783", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7788", "CVE-2017-7789", "CVE-2017-7790", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7794", "CVE-2017-7796", "CVE-2017-7797", "CVE-2017-7798", "CVE-2017-7799", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7804", "CVE-2017-7806", "CVE-2017-7807", "CVE-2017-7808", "CVE-2017-7809");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 10:04:00 +0000 (Wed, 01 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-18) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-18");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-18/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1353763%2C1353356%2C1370070%2C1375435%2C1373663%2C1363150%2C1370817%2C1273678%2C1367850%2C1347968%2C1361749%2C1349138%2C1371982%2C1344666%2C1369836%2C1330739%2C1371511%2C1371484");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1354443%2C1368576%2C1366903%2C1369913%2C1371424%2C1346590%2C1371890%2C1372985%2C1362924%2C1368105%2C1369994%2C1371283%2C1368362%2C1378826%2C1380426%2C1368030%2C1373220%2C1321384%2C1383002");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1371586%2C1372112");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1073952");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1074642");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1234401");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322896");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1334776");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1344034");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1350460");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1352039");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1353312");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356985");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1360842");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1365189");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1365875");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1367531");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1368652");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1371259");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1372509");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1372849");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1374047");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1374281");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1376087");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1376459");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1377426");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1378113");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1378147");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1380284");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-7798: XUL injection in the style editor in devtools
The Developer Tools feature suffers from a XUL injection vulnerability due to improper sanitization of the web page source code. In the worst case, this could allow arbitrary code execution when opening a malicious page with the style editor tool.

CVE-2017-7800: Use-after-free in WebSockets during disconnection
A use-after-free vulnerability can occur in WebSockets when the object holding the connection is freed before the disconnection operation is finished. This results in an exploitable crash.

CVE-2017-7801: Use-after-free with marquee during window resizing
A use-after-free vulnerability can occur while re-computing layout for a marquee element during window resizing where the updated style object is freed while still in use. This results in a potentially exploitable crash.

CVE-2017-7809: Use-after-free while deleting attached editor DOM node
A use-after-free vulnerability can occur when an editor DOM node is deleted prematurely during tree traversal while still bound to the document. This results in a potentially exploitable crash.

CVE-2017-7784: Use-after-free with image observers
A use-after-free vulnerability can occur when reading an image observer during frame reconstruction after the observer has been freed. This results in a potentially exploitable crash.

CVE-2017-7802: Use-after-free resizing image elements
A use-after-free vulnerability can occur when manipulating the DOM during the resize event of an image element. If these elements have been freed due to a lack of strong references, a potentially exploitable crash may occur when the freed elements are accessed.

CVE-2017-7785: Buffer overflow manipulating ARIA attributes in DOM
A buffer overflow can occur when manipulating Accessible Rich Internet Applications (ARIA) attributes within the DOM. This results in a potentially exploitable crash.

CVE-2017-7786: Buffer overflow while painting non-displayable SVG
A buffer overflow can occur when the image renderer attempts to paint non-displayable SVG elements. This results in a potentially exploitable crash.

CVE-2017-7806: Use-after-free in layer manager with SVG
A use-after-free vulnerability can occur when the layer manager is freed too early when rendering specific SVG content, resulting in a potentially exploitable crash.

CVE-2017-7753: Out-of-bounds read with cached style data and pseudo-elements
An out-of-bounds read occurs when applying style rules to pseudo-elements, such as ::first-line, using cached style data.

CVE-2017-7787: Same-origin policy bypass with iframes through page reloads
Same-origin policy protections can be bypassed on pages with embedded iframes during page reloads, allowing the iframes to access content on the top level page, leading to information disclosure.

CVE-2017-7807: Domain hijacking through AppCache fallback
A mechanism that uses AppCache to hijack a URL ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 55.");

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

if (version_is_less(version: version, test_version: "55")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "55", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
