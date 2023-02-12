# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.826758");
  script_cve_id("CVE-2021-29980", "CVE-2021-29981", "CVE-2021-29982", "CVE-2021-29984",
                "CVE-2021-29985", "CVE-2021-29988", "CVE-2021-29989", "CVE-2021-29990");
  script_tag(name:"creation_date", value:"2023-01-10 15:43:23 +0530 (Tue, 10 Jan 2023)");
  script_version("2023-01-11T10:12:37+0000");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-25 02:08:00 +0000 (Wed, 25 Aug 2021)");
  script_name("Mozilla Firefox Security Advisory (MFSA2021-33) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_xref(name:"Advisory-ID", value:"MFSA2021-33");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-33/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1544190%2C1716481%2C1717778%2C1719319%2C1722073");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1662676%2C1666184%2C1719178%2C1719998%2C1720568");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1696138");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1707774");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1715318");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1716129");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1717922");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1720031");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1722083");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1722204");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-29981: Live range splitting could have led to conflicting assignments in the JIT
An issue present in lowering/register allocation could have led to obscure but deterministic register confusion failures in JITted code that would lead to a potentially exploitable crash.

CVE-2021-29988: Memory corruption as a result of incorrect style treatment
Firefox incorrectly treated an inline list-item element as a block element, resulting in an out of bounds read or memory corruption, and a potentially exploitable crash.

CVE-2021-29984: Incorrect instruction reordering during JIT optimization
Instruction reordering resulted in a sequence of instructions that would cause an object to be incorrectly considered during garbage collection. This led to memory corruption and a potentially exploitable crash.

CVE-2021-29980: Uninitialized memory in a canvas object could have led to memory corruption
Uninitialized memory in a canvas object could have caused an incorrect free() leading to memory corruption and a potentially exploitable crash.

CVE-2021-29982: Single bit data leak due to incorrect JIT optimization and type confusion
Due to incorrect JIT optimization, we incorrectly interpreted data from the wrong type of object, resulting in the potential leak of a single bit of memory.

CVE-2021-29989: Memory safety bugs fixed in Firefox 91 and Firefox ESR 78.13
Mozilla developers Christoph Kerschbaumer, Olli Pettay, Sandor Molnar, and Simon Giesecke reported memory safety bugs present in Firefox 90 and Firefox ESR 78.12. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 91.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "91")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "91", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
