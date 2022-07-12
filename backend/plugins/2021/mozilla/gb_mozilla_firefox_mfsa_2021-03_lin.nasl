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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.03");
  script_cve_id("CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23955", "CVE-2021-23956", "CVE-2021-23957", "CVE-2021-23958", "CVE-2021-23959", "CVE-2021-23960", "CVE-2021-23961", "CVE-2021-23962", "CVE-2021-23963", "CVE-2021-23964", "CVE-2021-23965");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-03 19:58:00 +0000 (Wed, 03 Mar 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-03) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-03");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-03/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1662507%2C1666285%2C1673526%2C1674278%2C1674835%2C1675097%2C1675844%2C1675868%2C1677590%2C1677888%2C1680410%2C1681268%2C1682068%2C1682938%2C1683736%2C1685260%2C1685925");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1670378%2C1673555%2C1676812%2C1678582%2C1684497");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1338637");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1584582");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1642747");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1659035");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1675755");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1677194");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1677940");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1680793");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1683940");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1684020");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1684837");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-23953: Cross-origin information leakage via redirected PDF requests
If a user clicked into a specifically crafted PDF, the PDF reader could be confused into leaking cross-origin information, when said information is served as chunked data.

CVE-2021-23954: Type confusion when using logical assignment operators in JavaScript switch statements
Using the new logical assignment operators in a JavaScript switch statement could have caused a type confusion, leading to a memory corruption and a potentially exploitable crash.

CVE-2021-23955: Clickjacking across tabs through misusing requestPointerLock
The browser could have been confused into transferring a pointer lock state into another tab, which could have lead to clickjacking attacks.

CVE-2021-23956: File picker dialog could have been used to disclose a complete directory
An ambiguous file picker design could have confused users who intended to select and upload a single file into uploading a whole directory. This was addressed by adding a new prompt.

CVE-2021-23957: Iframe sandbox could have been bypassed on Android via the intent URL scheme
Navigations through the Android-specific intent URL scheme could have been misused to escape iframe sandbox.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2021-23958: Screen sharing permission leaked across tabs
The browser could have been confused into transferring a screen sharing state into another tab, which would leak unintended information.

CVE-2021-23959: Cross-Site Scripting in error pages on Firefox for Android
An XSS bug in internal error pages could have led to various spoofing attacks, including other error pages and the address bar.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2021-23960: Use-after-poison for incorrectly redeclared JavaScript variables during GC
Performing garbage collection on re-declared JavaScript variables resulted in a user-after-poison, and a potentially exploitable crash.

CVE-2021-23961: More internal network hosts could have been probed by a malicious webpage
Further techniques that built on the slipstream research combined with a malicious webpage could have exposed both an internal network's hosts as well as services running on the user's local machine.

CVE-2021-23962: Use-after-poison in <code>nsTreeBodyFrame::RowCountChanged</code>
Incorrect use of the RowCountChanged method could have led to a user-after-poison and a potentially exploitable crash.

CVE-2021-23963: Permission prompt inaccessible after asking for additional permissions
When sharing geolocation during an active WebRTC share, Firefox could have reset the webRTC sharing state in the user interface, leading to loss of control over the currently granted permission

CVE-2021-23964: Memory safety bugs fixed in Firefox 85 and Firefox ESR 78.7
Mozilla developers Andrew ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 85.");

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

if (version_is_less(version: version, test_version: "85")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "85", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
