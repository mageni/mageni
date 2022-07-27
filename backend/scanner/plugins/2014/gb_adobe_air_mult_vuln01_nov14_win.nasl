###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln01_nov14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe AIR Multiple Vulnerabilities(APSB14-24)-(Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804796");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0573", "CVE-2014-0574", "CVE-2014-0576", "CVE-2014-0577",
                "CVE-2014-0581", "CVE-2014-0582", "CVE-2014-0583", "CVE-2014-0584",
                "CVE-2014-0585", "CVE-2014-0586", "CVE-2014-0588", "CVE-2014-0589",
                "CVE-2014-0590", "CVE-2014-8437", "CVE-2014-8438", "CVE-2014-8440",
                "CVE-2014-8441", "CVE-2014-8442");
  script_bugtraq_id(71033, 71041, 71037, 71038, 71042, 71039, 71035, 71043, 71044,
                    71045, 71048, 71051, 71046, 71036, 71049, 71047, 71050, 71040);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-14 11:33:04 +0530 (Fri, 14 Nov 2014)");
  script_name("Adobe AIR Multiple Vulnerabilities(APSB14-24)-(Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe AIR
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Flaws are due to,

  - An use-after-free error.

  - A double free error.

  - Multiple type confusion errors.

  - An error related to a permission issue.

  - Multiple unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe AIR version before 15.0.0.356
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Adobe AIR version
  15.0.0.356 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59978");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!airVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:airVer, test_version:"15.0.0.356"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
