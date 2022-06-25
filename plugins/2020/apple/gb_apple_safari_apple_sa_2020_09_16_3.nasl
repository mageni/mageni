# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817499");
  script_version("2020-09-29T06:11:49+0000");
  script_cve_id("CVE-2020-9948", "CVE-2020-9951", "CVE-2020-9952", "CVE-2020-9983");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-22 17:43:15 +0530 (Tue, 22 Sep 2020)");
  script_name("Apple Safari Security Updates(APPLE-SA-2020-09-16-3)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A type confusion issue related to improper memory handling,

  - A use after free issue related to improper memory management,

  - An input validation issue,

  - An out-of-bounds write issue related to improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct cross site scripting attacks and arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 14.0");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 14.0 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2020/Sep/38");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos['version'];
safPath = infos['location'];

if(version_is_less(version:safVer, test_version:"14.0"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"14.0", install_path:safPath);
  security_message(data:report);
  exit(0);
}
exit(0);
