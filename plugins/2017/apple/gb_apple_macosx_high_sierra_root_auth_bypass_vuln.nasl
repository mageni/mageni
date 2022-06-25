###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_high_sierra_root_auth_bypass_vuln.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple MacOSX High Sierra Local Root Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812305");
  script_version("$Revision: 14295 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-29 15:25:36 +0530 (Wed, 29 Nov 2017)");

  script_cve_id("CVE-2017-13872");

  script_name("Apple MacOSX High Sierra Local Root Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X High
  Sierra and is prone to local root authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error which
  allows anyone to log into system as root with empty password.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to gain administrative access to the system.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13.x");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://thehackernews.com/2017/11/mac-os-password-hack.html");
  script_xref(name:"URL", value:"https://techcrunch.com/2017/11/28/astonishing-os-x-bug-lets-anyone-log-into-a-high-sierra-machine");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208315");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13" || "Mac OS X" >!< osName){
  exit(0);
}

if(osVer == "10.13"){
  VULN = TRUE;
  install = osVer;
}

else if(osVer == "10.13.1")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(buildVer)
  {
    ## Based on https://en.wikipedia.org/wiki/MacOS_High_Sierra
    if(version_is_less(version:buildVer, test_version:"17B48")){
      VULN = TRUE;
      install = osVer + ' build ' + buildVer;
    }
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:install, fixed_version:"10.13.2");
  security_message(data:report);
  exit(0);
}

exit(99);