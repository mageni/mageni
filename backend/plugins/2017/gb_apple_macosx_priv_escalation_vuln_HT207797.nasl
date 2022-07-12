###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_priv_escalation_vuln_HT207797.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple Mac OS X Privilege Escalation Vulnerability-HT207797
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810985");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2017-2533");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-16 15:41:39 +0530 (Tue, 16 May 2017)");
  script_name("Apple Mac OS X Privilege Escalation Vulnerability-HT207797");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to poor filesystem
  restrictions");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain system privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x through
  10.11.6 and 10.12.x through 10.12.4");

  script_tag(name:"solution", value:"For Apple Mac OS X version 10.12.x before
  10.12.4 update to 10.12.5 and for versions 10.11.x through 10.11.6 apply the
  appropriate security patch from the reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207797");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[12]");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[12]" || "Mac OS X" >!< osName){
  exit(0);
}

## 10.11.6 before build 15G1510 is vulnerable
## if 10.11.5 or less is running, update to 10.11.6 then apply patch
if(osVer =~ "^10\.11")
{
  if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  ## applying patch on 10.11.6 will upgrade build version to 15G1510
  else if(version_is_equal(version:osVer, test_version:"10.11.6"))
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(buildVer && version_is_less(version:buildVer, test_version:"15G1510")){
      fix = "Apply patch from vendor";
    }
  }
}

## 10.12 to 10.12.4 is vulnerable
else if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.4")){
  fix = "10.12.5";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);