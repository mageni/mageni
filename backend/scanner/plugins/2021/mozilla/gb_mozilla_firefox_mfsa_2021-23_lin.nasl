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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.23");
  script_cve_id("CVE-2021-29959", "CVE-2021-29960", "CVE-2021-29961", "CVE-2021-29962", "CVE-2021-29963", "CVE-2021-29964", "CVE-2021-29965", "CVE-2021-29966", "CVE-2021-29967");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-07 08:15:00 +0000 (Wed, 07 Jul 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-23) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-23");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-23/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1602862%2C1703191%2C1703760%2C1704722%2C1706041");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1660307%2C1686154%2C1702948%2C1708124");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1395819");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1675965");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1700235");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1701673");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1705068");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1706501");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1709257");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-29965: Password Manager on Firefox for Android susceptible to domain spoofing
A malicious website that causes an HTTP Authentication dialog to be spawned could trick the built-in password manager to suggest passwords for the currently active website instead of the website that triggered the dialog.
This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2021-29960: Filenames printed from private browsing mode incorrectly retained in preferences
Firefox used to cache the last filename used for printing a file. When generating a filename for printing, Firefox usually suggests the web page title.
The caching and suggestion techniques combined may have lead to the title of a website visited during private browsing mode being stored on disk.

CVE-2021-29961: Firefox UI spoof using `<select>` elements and CSS scaling
When styling and rendering an oversized <select> element, Firefox did not apply correct clipping which allowed an attacker to paint over the user interface.

CVE-2021-29963: Shared cookies for search suggestions in private browsing mode
Address bar search suggestions in private browsing mode were re-using session data from normal mode.
This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2021-29964: Out of bounds-read when parsing a `WM_COPYDATA` message
A locally-installed hostile program could send WM_COPYDATA messages that Firefox would process incorrectly, leading to an out-of-bounds read. This bug only affects Firefox on Windows. Other operating systems are unaffected.

CVE-2021-29959: Devices could be re-enabled without additional permission prompt
When a user has already allowed a website to access microphone and camera, disabling camera sharing would not fully prevent the website from re-enabling it without an additional prompt.
This was only possible if the website kept recording with the microphone until re-enabling the camera.

CVE-2021-29962: No rate-limiting for popups on Firefox for Android
Firefox for Android would become unstable and hard-to-recover when a website opened too many popups.
This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2021-29967: Memory safety bugs fixed in Firefox 89 and Firefox ESR 78.11
Mozilla developers Christian Holler, Anny Gakhokidze, Alexandru Michis, Gabriele Svelto reported memory safety bugs present in Firefox 88 and Firefox ESR 78.11. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2021-29966: Memory safety bugs fixed in Firefox 89
Mozilla developers Christian Holler, Tooru Fujisawa, Tyson Smith reported memory safety bugs present in Firefox 88. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 89.");

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

if (version_is_less(version: version, test_version: "89")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "89", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
