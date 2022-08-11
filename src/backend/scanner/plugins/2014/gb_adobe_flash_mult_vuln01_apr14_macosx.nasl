###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_mult_vuln01_apr14_macosx.nasl 2014-04-01 12:40:22Z Apr$
#
# Adobe Flash Player Multiple Vulnerabilities - 01 Apr14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804351");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0510");
  script_bugtraq_id(66241);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-01 12:45:19 +0530 (Tue, 01 Apr 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 Apr14 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to some unspecified error caused by improper validation of
user-supplied input.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct denial of service or
potentially execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Flash Player version 12.0.0.77 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade Flash Player to version 13.0.0.182 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1029969");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14033103");
  script_xref(name:"URL", value:"http://www.pwn2own.com/2014/03/pwn2own-results-thursday-day-two");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:playerVer, test_version:"12.0.0.77"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
