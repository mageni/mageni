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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.10");
  script_cve_id("CVE-2022-0843", "CVE-2022-26381", "CVE-2022-26382", "CVE-2022-26383", "CVE-2022-26384", "CVE-2022-26385", "CVE-2022-26387");
  script_tag(name:"creation_date", value:"2022-04-27 10:37:55 +0000 (Wed, 27 Apr 2022)");
  script_version("2022-04-27T10:37:55+0000");
  script_tag(name:"last_modification", value:"2022-04-27 10:37:55 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-04-27 10:37:55 +0000 (Wed, 27 Apr 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-10) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-10");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-10/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1746523%2C1749062%2C1749164%2C1749214%2C1749610%2C1750032%2C1752100%2C1752405%2C1753612%2C1754508");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1736243");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1741888");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1742421");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1744352");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1747526");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1752979");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-26383: Browser window spoof using fullscreen mode
When resizing a popup after requesting fullscreen access, the popup would not display the fullscreen notification.

CVE-2022-26384: iframe allow-scripts sandbox bypass
If an attacker could control the contents of an iframe sandboxed with allow-popups but not allow-scripts, they were able to craft a link that, when clicked, would lead to JavaScript execution in violation of the sandbox.

CVE-2022-26387: Time-of-check time-of-use bug when verifying add-on signatures
When installing an add-on, Firefox verified the signature before prompting the user, but while the user was confirming the prompt, the underlying add-on file could have been modified and Firefox would not have noticed.

CVE-2022-26381: Use-after-free in text reflows
An attacker could have caused a use-after-free by forcing a text reflow in an SVG object leading to a potentially exploitable crash.

CVE-2022-26382: Autofill Text could be exfiltrated via side-channel attacks
While the text displayed in Autofill tooltips cannot be directly read by JavaScript, the text was rendered using page fonts. Side-channel attacks on the text by using specially crafted fonts could have lead to this text being inferred by the webpage.

CVE-2022-26385: Use-after-free in thread shutdown
In unusual circumstances, an individual thread may outlive the thread's manager during shutdown. This could have led to a use-after-free causing a potentially exploitable crash.

CVE-2022-0843: Memory safety bugs fixed in Firefox 98
Mozilla developers Kershaw Chang, Ryan VanderMeulen, and Randell Jesup reported memory safety bugs present in Firefox 97. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 98.");

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

if (version_is_less(version: version, test_version: "98")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "98", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
