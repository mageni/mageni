###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Air Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803443");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2013-0630");
  script_bugtraq_id(57184);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2013-03-21 13:10:21 +0530 (Thu, 21 Mar 2013)");
  script_name("Adobe Air Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51771");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027950");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial of service condition.");
  script_tag(name:"affected", value:"Adobe AIR version 3.5.0.880 and earlier on Windows");
  script_tag(name:"insight", value:"An integer overflow error within 'flash.display.BitmapData()', which can be
  exploited to cause a heap-based buffer overflow.");
  script_tag(name:"solution", value:"Update to Adobe Air version 3.5.0.1060 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Air and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"3.5.0.1060" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.0.1060", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );