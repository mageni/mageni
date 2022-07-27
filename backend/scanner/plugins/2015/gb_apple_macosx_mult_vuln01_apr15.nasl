###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-01 Apr15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805601");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2015-1130", "CVE-2015-1131", "CVE-2015-1132", "CVE-2015-1133",
                "CVE-2015-1134", "CVE-2015-1135", "CVE-2015-1136", "CVE-2015-1088",
                "CVE-2015-1089", "CVE-2015-1091", "CVE-2015-1093", "CVE-2015-1137",
                "CVE-2015-1138", "CVE-2015-1139", "CVE-2015-1140", "CVE-2015-1141",
                "CVE-2015-1142", "CVE-2015-1143", "CVE-2015-1144", "CVE-2015-1145",
                "CVE-2015-1146", "CVE-2015-1147", "CVE-2015-1148", "CVE-2015-1095",
                "CVE-2015-1098", "CVE-2015-1099", "CVE-2015-1100", "CVE-2015-1101",
                "CVE-2015-1102", "CVE-2015-1103", "CVE-2015-1104", "CVE-2015-1105",
                "CVE-2015-1117", "CVE-2015-1118");
  script_bugtraq_id(73982, 73984, 72328, 73981);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-04-24 15:41:40 +0530 (Fri, 24 Apr 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 Apr15");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code with system privilege, man-in-the-middle
  attack, remote attacker to bypass network filters, to cause a denial of
  service, a context-dependent attacker to corrupt memory and cause a denial of
  service, bypass signature validation or potentially execute arbitrary code, a
  local application to gain elevated privileges by using a compromised service
  and some unspecified impacts.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.8 through
  10.8.5, 10.9 through 10.9.5, and 10.10.x through 10.10.2");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.10.3
  or later or apply security update 2015-004 for 10.8 and 10.9 versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/kb/HT204659");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.([89]|10)");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.([89]|10)" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.8.5") || (osVer == "10.9.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.8.5" && version_is_less(version:buildVer, test_version:"12F2518"))
  {
    fix = "Apply Security Update 2015-004";
    osVer = osVer + " Build " + buildVer;
  }

  else if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F1077"))
  {
    fix = "Apply Security Update 2015-004";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.8")
{
  if(version_is_less(version:osVer, test_version:"10.8.5")){
    fix = "Upgrade to latest OS release 10.8.5 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.9")
{
  if(version_is_less(version:osVer, test_version:"10.9.5")){
    fix = "Upgrade to latest OS release 10.9.5 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.10")
{
  if(version_is_less(version:osVer, test_version:"10.10.3")){
    fix = "10.10.3";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);