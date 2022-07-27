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

CPE = "cpe:/a:adobe:bridge_cc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814795");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-7130", "CVE-2019-7132", "CVE-2019-7133", "CVE-2019-7134",
                "CVE-2019-7135", "CVE-2019-7138", "CVE-2019-7136", "CVE-2019-7137");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 13:48:50 +0530 (Thu, 11 Apr 2019)");
  script_name("Adobe Bridge CC Security Updates (apsb19-25)-Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe Bridge
  CC and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A heap-overflow error.

  - An out-of-bounds write error.

  - A use after free error.

  - A memory corruption error.

  - Multiple out-of-bounds read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or gain access to potentially sensitive
  information.");

  script_tag(name:"affected", value:"Adobe Bridge CC before version 9.0.3");

  script_tag(name:"solution", value:"Upgrade to Adobe Bridge CC 9.0.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://creative.adobe.com/products/download/bridge");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb19-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

## 9.0.3 == 9.0.3.279
if(version_is_less(version:vers, test_version:"9.0.3.279"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"9.0.3 (9.0.3.279)", install_path:path);
  security_message(data:report);
  exit(0);
}
