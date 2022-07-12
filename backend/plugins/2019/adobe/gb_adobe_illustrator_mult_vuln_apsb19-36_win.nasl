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

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815842");
  script_version("2019-11-14T12:44:20+0000");
  script_cve_id("CVE-2019-7962", "CVE-2019-8247", "CVE-2019-8248");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-11-14 12:44:20 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 12:20:15 +0530 (Thu, 14 Nov 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Illustrator Multiple Vulnerabilities-Windows (apsb19-36)");

  script_tag(name:"summary", value:"The host is installed with Adobe Illustrator
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insecure library loading error.

  - Multiple memory corruption errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and escalate privileges on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator CC 2019 23.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator CC 2019 version
  24.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb19-36.html");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_win.nasl");
  script_mandatory_keys("Adobe/Illustrator/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
adobeVer = infos['version'];
adobePath = infos['location'];

if(version_in_range(version:adobeVer, test_version:"23.0", test_version2:"23.1.0"))
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:'24.0', install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
