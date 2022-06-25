###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Illustrator Privilege Escalation Vulnerability-Windows (332644)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813498");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2006-0525");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-12 17:32:37 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod", value:"30"); #solution is a patch
  script_name("Adobe Illustrator Privilege Escalation Vulnerability-Windows (332644)");

  script_tag(name:"summary", value:"The host is installed with Adobe Illustrator
  and is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in application
  which installs a large number of '.EXE' and '.DLL' files with write-access
  permission for the Everyone group.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain elevated privilege.");

  script_tag(name:"affected", value:"Adobe Illustrator CS2 on Windows.");

  script_tag(name:"solution", value:"Apply patch from vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/downloads/detail.jsp?ftpID=3308");
  script_xref(name:"URL", value:"http://www.adobe.com/support/downloads/detail.jsp?ftpID=3307");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(adobeVer =~ "^12\.")
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:"Apply Patch", install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
