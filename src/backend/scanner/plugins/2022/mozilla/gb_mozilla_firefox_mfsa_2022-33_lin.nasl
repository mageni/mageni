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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.33");
  script_cve_id("CVE-2022-38472", "CVE-2022-38473", "CVE-2022-38474", "CVE-2022-38475", "CVE-2022-38477", "CVE-2022-38478");
  script_tag(name:"creation_date", value:"2022-08-24 06:50:08 +0000 (Wed, 24 Aug 2022)");
  script_version("2022-08-24T06:50:08+0000");
  script_tag(name:"last_modification", value:"2022-08-24 06:50:08 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-33) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-33");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-33/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1760611%2C1770219%2C1771159%2C1773363");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1770630%2C1776658");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1719511");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1769155");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1771685");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1773266");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-38472: Address bar spoofing via XSLT error handling
An attacker could have abused XSLT error handling to associate attacker-controlled content with another origin which was displayed in the address bar. This could have been used to fool the user into submitting data intended for the spoofed origin.

CVE-2022-38473: Cross-origin XSLT Documents would have inherited the parent's permissions
A cross-origin iframe referencing an XSLT document would inherit the parent domain's permissions (such as microphone or camera access).

CVE-2022-38474: Recording notification not shown when microphone was recording on Android
A website that had permission to access the microphone could record audio without the audio notification being shown. This bug does not allow the attacker to bypass the permission prompt - it only affects the notification shown once permission has been granted.This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2022-38475: Attacker could write a value to a zero-length array
An attacker could have written a value to the first element in a zero-length JavaScript array. Although the array was zero-length, the value was not written to an invalid memory address.

CVE-2022-38477: Memory safety bugs fixed in Firefox 104 and Firefox ESR 102.2
Mozilla developer Nika Layzell and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 103 and Firefox ESR 102.1. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2022-38478: Memory safety bugs fixed in Firefox 104, Firefox ESR 102.2, and Firefox ESR 91.13
Members the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 103, Firefox ESR 102.1, and Firefox ESR 91.12. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 104.");

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

if (version_is_less(version: version, test_version: "104")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "104", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
