###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_flv_parsing_vuln_june15_lin.nasl 50169 2015-06-24 11:32:12Z jun$
#
# Adobe Flash Player Improper FLV Parsing Vulnerability June15 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805804");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3113");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-24 12:15:54 +0530 (Wed, 24 Jun 2015)");
  script_name("Adobe Flash Player Improper FLV Parsing Vulnerability June15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper parsing of
  Flash Video (FLV) files by Adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to downloaded a malicious flash file and create a back door results
  in taking complete control over the victim's system.");

  script_tag(name:"affected", value:"Adobe Flash Player versions before
  11.2.202.468 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.468 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/cve-2015-3113");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-14.html");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/38044/cyber-crime/adobe-fixed-cve-2015-3113.html");
  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html");
  script_xref(name:"URL", value:"http://blog.trendmicro.com/trendlabs-security-intelligence/adobe-issues-emergency-patch-for-flash-zero-day");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.468"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     11.2.202.468\n';
  security_message(data:report);
  exit(0);
}
