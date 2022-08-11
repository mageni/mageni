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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2016.94");
  script_cve_id("CVE-2016-9080", "CVE-2016-9893", "CVE-2016-9894", "CVE-2016-9895", "CVE-2016-9896", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9903", "CVE-2016-9904");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 14:52:00 +0000 (Tue, 07 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2016-94) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2016-94");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-94/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1289701%2C1314401%2C1315848");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1319524%2C1298773%2C1299098%2C1309834%2C1312609%2C1313212%2C1317805%2C1312548%2C1315631%2C1287912%2C1328642");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1301381");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1306628");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1312272");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1314442");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1315435");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1315543");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1317409");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1317936");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1319122");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1320039");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1320057");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-9894: Buffer overflow in SkiaGL
A buffer overflow in SkiaGl caused when a GrGLBuffer is truncated during allocation. Later writers will overflow the buffer, resulting in a potentially exploitable crash.

CVE-2016-9899: Use-after-free while manipulating DOM events and audio elements
Use-after-free while manipulating DOM events and removing audio elements due to errors in the handling of node adoption.

CVE-2016-9895: CSP bypass using marquee tag
Event handlers on marquee elements were executed despite a strict Content Security Policy (CSP) that disallowed inline JavaScript.

CVE-2016-9896: Use-after-free with WebVR
Use-after-free while manipulating the navigator object within WebVR. Note: WebVR is not currently enabled by default.

CVE-2016-9897: Memory corruption in libGLES
Memory corruption resulting in a potentially exploitable crash during WebGL functions using a vector constructor with a varying array within libGLES.

CVE-2016-9898: Use-after-free in Editor while manipulating DOM subtrees
Use-after-free resulting in potentially exploitable crash when manipulating DOM subtrees in the Editor.

CVE-2016-9900: Restricted external resources can be loaded by SVG images through data URLs
External resources that should be blocked when loaded by SVG images can bypass security restrictions through the use of data: URLs. This could allow for cross-domain data leakage.

CVE-2016-9904: Cross-origin information leak in shared atoms
An attacker could use a JavaScript Map/Set timing attack to determine whether an atom is used by another compartment/zone in specific contexts. This could be used to leak information, such as usernames embedded in JavaScript code, across websites.

CVE-2016-9901: Data from Pocket server improperly sanitized before execution
HTML tags received from the Pocket server will be processed without sanitization and any JavaScript code executed will be run in the about:pocket-saved (unprivileged) page, giving it access to Pocket's messaging API through HTML injection.

CVE-2016-9902: Pocket extension does not validate the origin of events
The Pocket toolbar button, once activated, listens for events fired from it's own pages but does not verify the origin of incoming events. This allows content from other origins to fire events and inject content and commands into the Pocket context. Note: this issue does not affect users with e10s enabled.

CVE-2016-9903: XSS injection vulnerability in add-ons SDK
Mozilla's add-ons SDK had a world-accessible resource with an HTML injection vulnerability. If an additional vulnerability allowed this resource to be loaded as a document it could allow injecting content and script into an add-on's context.

CVE-2016-9080: Memory safety bugs fixed in Firefox 50.1
Mozilla developers and community members Kan-Ru Chen, Christian Holler, and Tyson Smith reported memory safety bugs present in Firefox 50.0.2. Some of these bugs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 50.1.");

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

if (version_is_less(version: version, test_version: "50.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "50.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
