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

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821129");
  script_version("2022-06-17T06:43:01+0000");
  script_cve_id("CVE-2022-28839", "CVE-2022-28840", "CVE-2022-28841", "CVE-2022-28842",
                "CVE-2022-28843", "CVE-2022-28844", "CVE-2022-28845", "CVE-2022-28846",
                "CVE-2022-28847", "CVE-2022-28848", "CVE-2022-28849", "CVE-2022-28850");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-17 09:50:23 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-16 22:28:22 +0530 (Thu, 16 Jun 2022)");
  script_name("Adobe Bridge Multiple Vulnerabilities (APSB22-25) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe June update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An Improper Input Validation.

  - An Use After Free error.

  - An Out-of-bounds Read error.

  - Multiple Out-of-bounds Write errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution and memory leak on the system.");

  script_tag(name:"affected", value:"Adobe Bridge 12.0.1 and earlier versions on
  Windows.");

  script_tag(name:"solution", value:"Update to Adobe Bridge version 12.0.2
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb22-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"12.0.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.2 or later", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
