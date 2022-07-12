# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815861");
  script_version("2019-12-11T08:00:09+0000");
  script_tag(name:"last_modification", value:"2019-12-11 08:00:09 +0000 (Wed, 11 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-06 12:34:34 +0530 (Fri, 06 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2019-19479", "CVE-2019-19480", "CVE-2019-19481");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("OpenSC Multiple Vulnerabilities-Dec19 (Windows)");
  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opensc_detect_win.nasl");
  script_mandatory_keys("opensc/win/detected");

  script_tag(name:"summary", value:"This host is installed with OpenSC and is prone
  to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The libopensc/card-setcos.c has an incorrect read operation during parsing
    of a SETCOS file attribute.

  - The libopensc/pkcs15-prkey.c has an incorrect free operation in
    sc_pkcs15_decode_prkdf_entry.

  - The libopensc/card-cac1.c mishandles buffer limits for CAC certificates.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  execute arbitrary code or cause crash on affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"OpenSC through 0.19.0 and 0.20.x through 0.20.0-rc3.");
  script_tag(name:"solution", value:"Apply the provided patches or update to a newer version.");

  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/commit/c3f23b836e5a1766c36617fe1da30d22f7b63de2");
  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/commit/6ce6152284c47ba9b1d4fe8ff9d2e6a3f5ee02c7");
  script_xref(name:"URL", value:"https://github.com/OpenSC/OpenSC/commit/b75c002cfb1fd61cd20ec938ff4937d7b1a94278");

  exit(0);
}

CPE = "cpe:/a:opensc-project:opensc";

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version: vers, test_version: "0.19.0") ||
   ((revcomp(a: vers, b: "0.20.0") >= 0) && (revcomp(a: vers, b: "0.20.0-rc3") <= 0)))
{
  report = report_fixed_ver(installed_version: vers, fixed_version: "Apply patch from vendor", install_path: path);
  security_message(data: report);
  exit(0);
}

exit(99);
