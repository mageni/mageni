###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_robo_help_server_apsb16-12_win.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Adobe Robo Help Server Security Hotfix APSB16-12 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:robohelp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807673");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-1035");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-18 16:13:45 +0530 (Mon, 18 Apr 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Robo Help Server Security Hotfix APSB16-12 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Robo help
  server and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to mishandling of SQL queries");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to obtain sensitive information via unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Robo Help Server versions 9.x
  through 9.0.1 on Windows.");

  script_tag(name:"solution", value:"Apply the hotfix for Adobe Robo Help Server.

  - ---
  NOTE: If the patch is already applied, please ignore.

  - ---");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp-server/apsb16-12.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_detect_win.nasl");
  script_mandatory_keys("Adobe/RoboHelp/Server/Win/Ver");
  script_xref(name:"URL", value:"https://helpx.adobe.com/robohelp-server/kb/SQL-security-issue.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!roboVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:roboVer, test_version:"9", test_version2:"9.0.1"))
{
  report = report_fixed_ver(installed_version:roboVer, fixed_version:"Apply the Hotfix");
  security_message(data:report);
  exit(0);
}
