###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_flv_parsing_vuln_june15_win.nasl 50169 2015-06-24 11:32:12Z jun$
#
# Adobe Flash Player Improper FLV Parsing Vulnerability June15 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805802");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3113");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-24 11:58:55 +0530 (Wed, 24 Jun 2015)");
  script_name("Adobe Flash Player Improper FLV Parsing Vulnerability June15 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/cve-2015-3113");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-14.html");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/38044/cyber-crime/adobe-fixed-cve-2015-3113.html");
  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html");
  script_xref(name:"URL", value:"http://blog.trendmicro.com/trendlabs-security-intelligence/adobe-issues-emergency-patch-for-flash-zero-day");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper parsing of
  Flash Video (FLV) files by Adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to downloaded a malicious flash file and create a back door results
  in taking complete control over the victim's system.");

  script_tag(name:"affected", value:"Adobe Flash Player versions before
  13.0.0.296 and 14.x through 18.x before 18.0.0.194 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.296 or 18.0.0.194 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"13.0.0.296" ) ) {
  fix = "13.0.0.296";
  VULN = TRUE;
} else if( version_in_range( version:vers, test_version:"14.0", test_version2:"18.0.0.193" ) ) {
  fix = "18.0.0.194";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );