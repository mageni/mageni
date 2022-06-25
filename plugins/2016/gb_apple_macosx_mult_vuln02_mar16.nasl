###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-02 March-2016
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806695");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-1754", "CVE-2016-1755", "CVE-2016-1759", "CVE-2016-1761",
                "CVE-2016-1765", "CVE-2015-8472", "CVE-2015-1819", "CVE-2015-5312",
                "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7942", "CVE-2015-8035",
                "CVE-2015-8242", "CVE-2016-1762", "CVE-2016-0777", "CVE-2016-0778",
                "CVE-2015-5333", "CVE-2015-5334", "CVE-2014-9495", "CVE-2015-0973",
                "CVE-2016-1791", "CVE-2016-1800", "CVE-2016-1833", "CVE-2016-1834",
                "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838",
                "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-1841", "CVE-2016-1847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:35 +0530 (Fri, 01 Apr 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 March-2016");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details
  refer the reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, trigger a dialing action via a
  tel: URL, bypass a code-signing protection mechanism.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.9.x before 10.9.5
  and 10.10.x before 10.10.5");

  script_tag(name:"solution", value:"Apply the appropriate security patch from
  the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206567");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(9|10)");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.(9|10)"){
  exit(0);
}

if((osVer == "10.9.5") || (osVer == "10.10.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1808"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
  else if(osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1808"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

else if(version_in_range(version:osVer, test_version:"10.9", test_version2:"10.9.4")){
  fix = "10.9.5 build 13F1808";
}
else if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
  fix = "10.10.5 build 14F1808";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);