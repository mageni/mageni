# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.51");
  script_cve_id("CVE-2022-46871", "CVE-2022-46872", "CVE-2022-46873", "CVE-2022-46874", "CVE-2022-46877", "CVE-2022-46878", "CVE-2022-46879");
  script_tag(name:"creation_date", value:"2022-12-14 08:18:12 +0000 (Wed, 14 Dec 2022)");
  script_version("2022-12-14T10:20:42+0000");
  script_tag(name:"last_modification", value:"2022-12-14 10:20:42 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-51) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-51");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-51/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1736224%2C1793407%2C1794249%2C1795845%2C1797682%2C1797720%2C1798494%2C1799479");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1782219%2C1797370%2C1797685%2C1801102%2C1801315%2C1802395");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1644790");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1746139");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1795139");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1795697");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1799156");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-46871: libusrsctp library out of date
An out of date library (libusrsctp) contained vulnerabilities that could potentially be exploited.

CVE-2022-46872: Arbitrary file read from a compromised content process
An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary files via clipboard-related IPC messages.This bug only affects Firefox for Linux. Other operating systems are unaffected.

CVE-2022-46873: Firefox did not implement the CSP directive unsafe-hashes
Because Firefox did not implement the unsafe-hashes CSP directive, an attacker who was able to inject markup into a page otherwise protected by a Content Security Policy may have been able to inject executable script. This would be severely constrained by the specified Content Security Policy of the document.

CVE-2022-46874: Drag and Dropped Filenames could have been truncated to malicious extensions
A file with a long filename could have had its filename truncated to remove the valid extension, leaving a malicious extension in its place. This could have potentially led to user confusion and the execution of malicious code.

CVE-2022-46877: Fullscreen notification bypass
By confusing the browser, the fullscreen notification could have been delayed or suppressed, resulting in potential user confusion or spoofing attacks.

CVE-2022-46878: Memory safety bugs fixed in Firefox 108 and Firefox ESR 102.6
Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 107 and Firefox ESR 102.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2022-46879: Memory safety bugs fixed in Firefox 108
Mozilla developers and community members Lukas Bernhard, Gabriele Svelto, Randell Jesup, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 107. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 108.");

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

if (version_is_less(version: version, test_version: "108")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "108", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
