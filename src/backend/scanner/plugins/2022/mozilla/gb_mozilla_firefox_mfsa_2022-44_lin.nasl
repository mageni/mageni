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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.44");
  script_cve_id("CVE-2022-42927", "CVE-2022-42928", "CVE-2022-42929", "CVE-2022-42930", "CVE-2022-42931", "CVE-2022-42932");
  script_tag(name:"creation_date", value:"2022-10-19 09:20:00 +0000 (Wed, 19 Oct 2022)");
  script_version("2022-10-20T10:12:23+0000");
  script_tag(name:"last_modification", value:"2022-10-20 10:12:23 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-44) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-44");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-44/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1789729%2C1791363%2C1792041");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1780571");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1789128");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1789439");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1789503");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1791520");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-42927: Same-origin policy violation could have leaked cross-origin URLs
A same-origin policy violation could have allowed the theft of cross-origin URL entries, leaking the result of a redirect, via performance.getEntries().

CVE-2022-42928: Memory Corruption in JS Engine
Certain types of allocations were missing annotations that, if the Garbage Collector was in a specific state, could have lead to memory corruption and a potentially exploitable crash.

CVE-2022-42929: Denial of Service via window.print
If a website called window.print() in a particular way, it could cause a denial of service of the browser, which may persist beyond browser restart depending on the user's session restore settings.

CVE-2022-42930: Race condition in DOM Workers
If two Workers were simultaneously initializing their CacheStorage, a data race could have occurred in the ThirdPartyUtil component.

CVE-2022-42931: Username saved to a plaintext file on disk
Logins saved by Firefox should be managed by the Password Manager component which uses encryption to save files on-disk. Instead, the username (not password) was saved by the Form Manager to an unencrypted file on disk.

CVE-2022-42932: Memory safety bugs fixed in Firefox 106 and Firefox ESR 102.4
Mozilla developers Ashley Hale and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 105 and Firefox ESR 102.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 106.");

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

if (version_is_less(version: version, test_version: "106")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "106", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
