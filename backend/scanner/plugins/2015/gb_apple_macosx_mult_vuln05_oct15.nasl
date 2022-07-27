###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-05 October-15
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806149");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2014-4416", "CVE-2014-4403", "CVE-2014-4402", "CVE-2014-4401",
                "CVE-2014-4400", "CVE-2014-4399", "CVE-2014-4398", "CVE-2014-4397",
                "CVE-2014-4396", "CVE-2014-4395", "CVE-2014-4394", "CVE-2014-4393",
                "CVE-2014-4390", "CVE-2014-4376", "CVE-2014-4350", "CVE-2014-1391");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-29 14:23:09 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-05 October-15");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service, write to
  arbitrary files, execute arbitrary code with system privilege.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.7.x through
  10.7.5 prior to security update 2014-004, 10.8.x through 10.8.5 prior to
  security update 2014-004 and 10.9.x before 10.9.5");

  script_tag(name:"solution", value:"Upgrade Apple Mac OS X 10.9.x to version
  10.9.5 or later or apply appropriate patch for Apple Mac OS X 10.7.x and 10.8.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT204532");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[7-9]");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.[7-9]"){
  exit(0);
}

if(osVer =~ "^10\.[78]")
{
  if(version_in_range(version:osVer, test_version:"10.7", test_version2:"10.8.4") ||
     version_in_range(version:osVer, test_version:"10.8", test_version2:"10.7.4")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.7.5" || osVer == "10.8.5")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(buildVer)
    {
      if((osVer == "10.7.5" && version_is_less(version:buildVer, test_version:"12F2518")) ||
         (osVer == "10.8.5" && version_is_less(version:buildVer, test_version:"13F1077")))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4")){
  fix = "10.9.5";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);