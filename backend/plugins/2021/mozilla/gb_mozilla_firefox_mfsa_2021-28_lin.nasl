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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.28");
  script_cve_id("CVE-2021-29970", "CVE-2021-29971", "CVE-2021-29972", "CVE-2021-29973", "CVE-2021-29974", "CVE-2021-29975", "CVE-2021-29976", "CVE-2021-29977", "CVE-2021-30547");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-12 14:53:00 +0000 (Thu, 12 Aug 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-28) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-28");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-28/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1665836%2C1686138%2C1704316%2C1706314%2C1709931%2C1712084%2C1712357%2C1714066");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1700895%2C1703334%2C1706910%2C1711576%2C1714391");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1696816");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1701932");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1704843");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1709976");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1713259");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1713638");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1715766");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-29970: Use-after-free in accessibility features of a document
A malicious webpage could have triggered a use-after-free, memory corruption, and a potentially exploitable crash. This bug only affected Firefox when accessibility was enabled.

CVE-2021-29971: Granted permissions only compared host, omitting scheme and port on Android
If a user had granted a permission to a webpage and saved that grant, any webpage running on the same host - irrespective of scheme or port - would be granted that permission.This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2021-30547: Out of bounds write in ANGLE
An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially exploitable crash.

CVE-2021-29972: Use of out-of-date library included use-after-free vulnerability
A user-after-free vulnerability was found via testing, and traced to an out-of-date Cairo library. Updating the library resolved the issue, and may have remediated other, unknown security vulnerabilities as well.

CVE-2021-29973: Password autofill on HTTP websites was enabled without user interaction on Android
Password autofill was enabled without user interaction on insecure websites on Firefox for Android. This was corrected to require user interaction with the page before a user's password would be entered by the browser's autofill functionality.This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2021-29974: HSTS errors could be overridden when network partitioning was enabled
When network partitioning was enabled, e.g. as a result of Enhanced Tracking Protection settings, a TLS error page would allow the user to override an error on a domain which had specified HTTP Strict Transport Security (which implies that the error should not be override-able.) This issue did not affect the network connections, and they were correctly upgraded to HTTPS automatically.

CVE-2021-29975: Text message could be overlaid on top of another website
Through a series of DOM manipulations, a message, over which the attacker had control of the text but not HTML or formatting, could be overlaid on top of another domain (with the new domain correctly shown in the address bar) resulting in possible user confusion.

CVE-2021-29976: Memory safety bugs fixed in Firefox 90 and Firefox ESR 78.12
Mozilla developers Emil Ghitta, Tyson Smith, Valentin Gosu, Olli Pettay, and Randell Jesup reported memory safety bugs present in Firefox 89 and Firefox ESR 78.11. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2021-29977: Memory safety bugs fixed in Firefox 90
Mozilla developers Andrew McCreight, Tyson Smith, Christian Holler, and Gabriele Svelto reported memory safety bugs present in Firefox 89. Some of these bugs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 90.");

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

if (version_is_less(version: version, test_version: "90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "90", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
