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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.16");
  script_cve_id("CVE-2020-12387", "CVE-2020-12388", "CVE-2020-12389", "CVE-2020-12390", "CVE-2020-12391", "CVE-2020-12392", "CVE-2020-12393", "CVE-2020-12394", "CVE-2020-12395", "CVE-2020-12396", "CVE-2020-6831");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-15T10:47:05+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-12 22:15:00 +0000 (Fri, 12 Jun 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-16) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-16");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-16/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1339601%2C1611938%2C1620488%2C1622291%2C1627644");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1595886%2C1611482%2C1614704%2C1624098%2C1625749%2C1626382%2C1628076%2C1631508");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1141959");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1457100");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1545345");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1554110");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1614468");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1615471");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1618911");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1628288");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1632241");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-12387: Use-after-free during worker shutdown
A race condition when running shutdown code for Web Worker led to a use-after-free vulnerability. This resulted in a potentially exploitable crash.

CVE-2020-12388: Sandbox escape with improperly guarded Access Tokens
The Firefox content processes did not sufficiently lockdown access control which could result in a sandbox escape.Note: this issue only affects Firefox on Windows operating systems.

CVE-2020-12389: Sandbox escape with improperly separated process types
The Firefox content processes did not sufficiently lockdown access control which could result in a sandbox escape.Note: this issue only affects Firefox on Windows operating systems.

CVE-2020-6831: Buffer overflow in SCTP chunk input validation
A buffer overflow could occur when parsing and validating SCTP chunks in WebRTC. This could have led to memory corruption and a potentially exploitable crash.

CVE-2020-12390: Incorrect serialization of nsIPrincipal.origin for IPv6 addresses
Incorrect origin serialization of URLs with IPv6 addresses could lead to incorrect security checks

CVE-2020-12391: Content-Security-Policy bypass using object elements
Documents formed using data: URLs in an object element failed to inherit the CSP of the creating context. This allowed the execution of scripts that should have been blocked, albeit with a unique opaque origin.

CVE-2020-12392: Arbitrary local file access with 'Copy as cURL'
The 'Copy as cURL' feature of Devtools' network tab did not properly escape the HTTP POST data of a request, which can be controlled by the website. If a user used the 'Copy as cURL' feature and pasted the command into a terminal, it could have resulted in the disclosure of local files.

CVE-2020-12393: Devtools' 'Copy as cURL' feature did not fully escape website-controlled data, potentially leading to command injection
The 'Copy as cURL' feature of Devtools' network tab did not properly escape the HTTP method of a request, which can be controlled by the website. If a user used the 'Copy as cURL' feature and pasted the command into a terminal, it could have resulted in command injection and arbitrary command execution.Note: this issue only affects Firefox on Windows operating systems.

CVE-2020-12394: URL spoofing in location bar when unfocussed
A logic flaw in our location bar implementation could have allowed a local attacker to spoof the current location by selecting a different origin and removing focus from the input element.

CVE-2020-12395: Memory safety bugs fixed in Firefox 76 and Firefox ESR 68.8
Mozilla developers and community members Alexandru Michis, Jason Kratzer, philipp, Ted Campbell, Bas Schouten, Andre Bargull, and Karl Tomlinson reported memory safety bugs present in Firefox 75 and Firefox ESR 68.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 76.");

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

if (version_is_less(version: version, test_version: "76")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "76", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
