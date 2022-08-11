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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.06");
  script_cve_id("CVE-2018-5125", "CVE-2018-5126", "CVE-2018-5127", "CVE-2018-5128", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5131", "CVE-2018-5132", "CVE-2018-5133", "CVE-2018-5134", "CVE-2018-5135", "CVE-2018-5136", "CVE-2018-5137", "CVE-2018-5138", "CVE-2018-5140", "CVE-2018-5141", "CVE-2018-5142", "CVE-2018-5143");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-06 15:57:00 +0000 (Mon, 06 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-06) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-06");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-06/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1416529%2C1434580%2C1434384%2C1437450%2C1437507%2C1426988%2C1438425%2C1324042%2C1437087%2C1443865%2C1425520");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1433671%2C1414768%2C1416523%2C1425691%2C1441006%2C1429768%2C1426002%2C1297740%2C1435566%2C1432855%2C1442318%2C1421963%2C1422631%2C1426603%2C1404297%2C1425257%2C1373934%2C1423173%2C1416940");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1366357");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1408194");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1419166");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1422643");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1424261");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1428947");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1429093");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1429379");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1430511");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1430557");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1430974");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1431336");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1431371");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1432624");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1432870");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1433005");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1440775");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-5127: Buffer overflow manipulating SVG animatedPathSegList
A buffer overflow can occur when manipulating the SVG animatedPathSegList through script. This results in a potentially exploitable crash.

CVE-2018-5128: Use-after-free manipulating editor selection ranges
A use-after-free vulnerability can occur when manipulating elements, events, and selection ranges during editor operations. This results in a potentially exploitable crash.

CVE-2018-5129: Out-of-bounds write with malformed IPC messages
A lack of parameter validation on IPC messages results in a potential out-of-bounds write through malformed IPC messages. This can potentially allow for sandbox escape through memory corruption in the parent process.

CVE-2018-5130: Mismatched RTP payload type can trigger memory corruption
When packets with a mismatched RTP payload type are sent in WebRTC connections, in some circumstances a potentially exploitable crash is triggered.

CVE-2018-5131: Fetch API improperly returns cached copies of no-store/no-cache resources
Under certain circumstances the fetch() API can return transient local copies of resources that were sent with a no-store or no-cache cache header instead of downloading a copy from the network as it should. This can result in previously stored, locally cached data of a website being accessible to users if they share a common profile while browsing.

CVE-2018-5132: WebExtension Find API can search privileged pages
The Find API for WebExtensions can search some privileged pages, such as about:debugging, if these pages are open in a tab. This could allow a malicious WebExtension to search for otherwise protected data if a user has it open.

CVE-2018-5133: Value of the app.support.baseURL preference is not properly sanitized
If the app.support.baseURL preference is changed by a malicious local program to contain HTML and script content, this content is not sanitized. It will be executed if a user loads chrome://browser/content/preferences/in-content/preferences.xul directly in a tab and executes a search. This stored preference is also executed whenever an EME video player plugin displays a CDM-disabled message as a notification message.

CVE-2018-5134: WebExtensions may use view-source: URLs to bypass content restrictions
WebExtensions may use view-source: URLs to view local file: URL content, as well as content stored in about:cache, bypassing restrictions that only allow WebExtensions to view specific content.

CVE-2018-5135: WebExtension browserAction can inject scripts into unintended contexts
WebExtensions can bypass normal restrictions in some circumstances and use browser.tabs.executeScript to inject scripts into contexts where this should not be allowed, such as pages from other WebExtensions or unprivileged about: pages.

CVE-2018-5136: Same-origin policy violation with data: URL shared workers
A shared worker created from a data: URL in one ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 59.");

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

if (version_is_less(version: version, test_version: "59")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "59", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
