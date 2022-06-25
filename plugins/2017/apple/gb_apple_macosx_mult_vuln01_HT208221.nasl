###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_HT208221.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple MacOSX Multiple Vulnerabilities - 01 HT208221
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811961");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2017-13799", "CVE-2017-11108", "CVE-2017-11541", "CVE-2017-11542",
 		"CVE-2017-11543", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895",
		"CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899",
		"CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985",
		"CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989",
		"CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993",
		"CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997",
		"CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001",
		"CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005",
		"CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009",
		"CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013",
		"CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017",
		"CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021",
		"CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025",
		"CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029",
		"CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033",
		"CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037",
		"CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041",
		"CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045",
		"CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049",
		"CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053",
		"CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688",
		"CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");
  script_bugtraq_id(99938, 99941, 99940, 99939, 100913, 100914);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-02 12:40:42 +0530 (Thu, 02 Nov 2017)");
  script_name("Apple MacOSX Multiple Vulnerabilities - 01 HT208221");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple issues in tcpdump.

  - A memory corruption issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code with system privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13, 10.12.x
  through 10.12.6");

  script_tag(name:"solution", value:"For Apple Mac OS X version 10.13 update to
  version 10.13.1 and for versions 10.12.x through 10.12.6 apply the appropriate
  security patch from the reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208221");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[23]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[23]" || "Mac OS X" >!< osName){
  exit(0);
}

# if 10.12.x before 10.12.6 is running, update to 10.12.6 first and then apply patch
if(osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.12.6")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    # applying patch on 10.12.6 will upgrade build version to 16G1036
    # http://www.xlr8yourmac.com/index.html#MacNvidiaDriverUpdates
    if(buildVer)
    {
      if(version_is_less(version:buildVer, test_version:"16G1036"))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(osVer == "10.13"){
  fix = "10.13.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);