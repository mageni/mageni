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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.13");
  script_cve_id("CVE-2022-1097", "CVE-2022-24713", "CVE-2022-28281", "CVE-2022-28282", "CVE-2022-28283", "CVE-2022-28284", "CVE-2022-28285", "CVE-2022-28286", "CVE-2022-28287", "CVE-2022-28288", "CVE-2022-28289");
  script_tag(name:"creation_date", value:"2022-04-27 10:37:55 +0000 (Wed, 27 Apr 2022)");
  script_version("2022-04-27T10:37:55+0000");
  script_tag(name:"last_modification", value:"2022-04-27 10:37:55 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-17 21:29:00 +0000 (Thu, 17 Mar 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-13) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-13");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-13/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1663508%2C1744525%2C1753508%2C1757476%2C1757805%2C1758549%2C1758776");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1746415%2C1746495%2C1746500%2C1747282%2C1748759%2C1749056%2C1749786%2C1751679%2C1752120%2C1756010%2C1756017%2C1757213%2C1757258%2C1757427");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1735265");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1741515");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1745667");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1751609");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1754066");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1754522");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1755621");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1756957");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1758509");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-1097: Use-after-free in NSSToken objects
NSSToken objects were referenced via direct points, and could have been accessed in an unsafe way on different threads, leading to a use-after-free and potentially exploitable crash.

CVE-2022-28281: Out of bounds write due to unexpected WebAuthN Extensions
If a compromised content process sent an unexpected number of WebAuthN Extensions in a Register command to the parent process, an out of bounds write would have occurred leading to memory corruption and a potentially exploitable crash.

CVE-2022-28282: Use-after-free in DocumentL10n::TranslateDocument
By using a link with rel='localization' a use-after-free could have been triggered by destroying an object during JavaScript execution and then referencing the object through a freed pointer, leading to a potentially exploitable crash.

CVE-2022-28283: Missing security checks for fetching sourceMapURL
The sourceMapURL feature in devtools was missing security checks that would have allowed a webpage to attempt to include local files or other files that should have been inaccessible.

CVE-2022-28284: Script could be executed via svg's use element
SVG's <use> element could have been used to load unexpected content that could have executed script in certain circumstances. While the specification seems to allow this, other browsers do not, and web developers relied on this property for script security so gecko's implementation was aligned with theirs.

CVE-2022-28285: Incorrect AliasSet used in JIT Codegen
When generating the assembly code for MLoadTypedArrayElementHole, an incorrect AliasSet was used. In conjunction with another vulnerability this could have been used for an out of bounds memory read.

CVE-2022-28286: iframe contents could be rendered outside the border
Due to a layout change, iframe contents could have been rendered outside of its border. This could have led to user confusion or spoofing attacks.

CVE-2022-28287: Text Selection could crash Firefox
In unusual circumstances, selecting text could cause text selection caching to behave incorrectly, leading to a crash.

CVE-2022-24713: Denial of Service via complex regular expressions
The rust regex crate did not properly prevent crafted regular expressions from taking an arbitrary amount of time during parsing. If an attacker was able to supply input to this crate, they could have caused a denial of service in the browser.

CVE-2022-28289: Memory safety bugs fixed in Firefox 99 and Firefox ESR 91.8
Mozilla developers and community members Nika Layzell, Andrew McCreight, Gabriele Svelto, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 98 and Firefox ESR 91.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2022-28288: Memory safety bugs fixed in Firefox 99
Mozilla ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 99.");

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

if (version_is_less(version: version, test_version: "99")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "99", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
