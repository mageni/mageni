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

CPE = "cpe:/a:adobe:robohelp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821179");
  script_version("2022-07-14T06:41:19+0000");
  script_cve_id("CVE-2022-23201");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-14 06:41:19 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 09:06:05 +0530 (Wed, 13 Jul 2022)");
  script_name("Adobe Robo Help Server XSS Vulnerability (APSB22-10) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to XSS
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a cross site scripting
  vulnerability in Adobe RoboHelp Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Adobe Robo Help Server version 2020.0.7
  and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update to Adobe Robo Help Server to 2020.0.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp-server/apsb22-10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_detect_win.nasl");
  script_mandatory_keys("Adobe/RoboHelp/Server/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!roboVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:roboVer, test_version:"2020.0.7"))
{
  report = report_fixed_ver(installed_version:roboVer, fixed_version:"2020.0.8");
  security_message(data:report);
  exit(0);
}
