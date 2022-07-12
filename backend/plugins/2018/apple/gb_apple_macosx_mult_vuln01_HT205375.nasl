###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-01 (HT205375)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813191");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2014-4860", "CVE-2015-0235", "CVE-2015-0273", "CVE-2015-5924",
                "CVE-2015-5925", "CVE-2015-5926", "CVE-2015-5927", "CVE-2015-5933",
                "CVE-2015-5934", "CVE-2015-5936", "CVE-2015-5937", "CVE-2015-5939",
                "CVE-2015-5940", "CVE-2015-5942", "CVE-2015-6834", "CVE-2015-6835",
                "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838", "CVE-2015-6976",
                "CVE-2015-6977", "CVE-2015-6978", "CVE-2015-6980", "CVE-2015-6984",
                "CVE-2015-6985", "CVE-2015-6991", "CVE-2015-6992", "CVE-2015-6993",
                "CVE-2015-6996", "CVE-2015-7003", "CVE-2015-7009", "CVE-2015-7010",
                "CVE-2015-7018", "CVE-2015-7024");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-15 15:17:32 +0530 (Tue, 15 May 2018)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (HT205375)");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code, unexpected application termination, exercise unused
  EFI functions, overwrite arbitrary files and load arbitrary files.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.9.x through
  10.9.5 prior to build 13F1134, 10.10.x through 10.10.5 prior to build 14F1021,
  and 10.11.x prior to 10.11.1");

  script_tag(name:"solution", value:"Upgrade 10.11.x Apple Mac OS X to version
  10.11.1 or apply the appropriate patch for 10.10.x and 10.9.x Apple Mac OS X
  versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205375");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(9|1[01])");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.(9|1[01])"){
  exit(0);
}

if(osVer =~ "^10\.(9|10)")
{
  if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4") ||
     version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.9.5" || osVer == "10.10.5")
  {
    buildVer = get_kb_item("ssh/login/osx_build");
    if(buildVer)
    {
      if((osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1134")) ||
         (osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1021")))
      {
        fix = "Apply patch from vendor";
        osVer = osVer + " Build " + buildVer;
      }
    }
  }
}

else if(osVer =~ "^10\.11" && version_is_less(version:osVer, test_version:"10.11.1")){
  fix = "10.11.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);