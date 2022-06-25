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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.05");
  script_cve_id("CVE-2020-6796", "CVE-2020-6797", "CVE-2020-6798", "CVE-2020-6799", "CVE-2020-6800", "CVE-2020-6801");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-11 23:15:00 +0000 (Wed, 11 Mar 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-05) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-05");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-05/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1595786%2C1596706%2C1598543%2C1604851%2C1608580%2C1608785%2C1605777");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1601024%2C1601712%2C1604836%2C1606492");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1596668");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1602944");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1606596");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1610426");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-6796: Missing bounds check on shared memory read in the parent process
A content process could have modified shared memory relating to crash reporting information, crash itself, and cause an out-of-bound write. This could have caused memory corruption and a potentially exploitable crash.

CVE-2020-6797: Extensions granted downloads.open permission could open arbitrary applications on Mac OSX
By downloading a file with the .fileloc extension, a semi-privileged extension could launch an arbitrary application on the user's computer. The attacker is restricted as they are unable to download non-quarantined files or supply command line arguments to the application, limiting the impact.Note: this issue only occurs on Mac OSX. Other operating systems are unaffected.

CVE-2020-6798: Incorrect parsing of template tag could result in JavaScript injection
If a <template> tag was used in a <select%gt, tag, the parser could be confused and allow JavaScript parsing and execution when it should not be allowed. A site that relied on the browser behaving correctly could suffer a cross-site scripting vulnerability as a result.

CVE-2020-6799: Arbitrary code execution when opening pdf links from other applications, when Firefox is configured as default pdf reader
Command line arguments could have been injected during Firefox invocation as a shell handler for certain unsupported file types. This required Firefox to be configured as the default handler for a given file type and for a file downloaded to be opened in a third party application that insufficiently sanitized URL data. In that situation, clicking a link in the third party application could have been used to retrieve and execute files whose location was supplied through command line arguments. Note: This issue only affects Windows operating systems and when Firefox is configured as the default handler for non-default filetypes. Other operating systems are unaffected.

CVE-2020-6800: Memory safety bugs fixed in Firefox 73 and Firefox ESR 68.5
Mozilla developers and community members Raul Gurzau, Tyson Smith, Bob Clary, Liz Henry, and Christian Holler reported memory safety bugs present in Firefox 72 and Firefox ESR 68.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2020-6801: Memory safety bugs fixed in Firefox 73
Mozilla developers Jason Kratzer, Tyson Smith, and Christian Holler reported memory safety bugs present in Firefox 72. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 73.");

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

if (version_is_less(version: version, test_version: "73")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "73", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
