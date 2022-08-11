###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities -01 Mar15
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
  script_oid("1.3.6.1.4.1.25623.1.0.805483");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2014-8838", "CVE-2014-8837", "CVE-2014-8835", "CVE-2014-8834",
                "CVE-2014-8833", "CVE-2014-8832", "CVE-2014-8831", "CVE-2014-8830",
                "CVE-2014-8829", "CVE-2014-8828", "CVE-2014-8827", "CVE-2014-8826",
                "CVE-2014-8825", "CVE-2014-8824", "CVE-2014-8823", "CVE-2014-8822",
                "CVE-2014-8821", "CVE-2014-8820", "CVE-2014-8819", "CVE-2014-8817",
                "CVE-2014-8816", "CVE-2014-4499", "CVE-2014-4498", "CVE-2014-4497");
  script_bugtraq_id(72328);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-03-05 17:54:00 +0530 (Thu, 05 Mar 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities -01 Mar15");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"For more details about the
  vulnerabilities, refer the reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass sandbox restrictions, execution of arbitrary code,
  information disclosure, privilege escalation and conduct denial of service.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.10.x through
  10.10.1, 10.8.x through 10.8.5 and 10.9.x through 10.9.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.10.2
  or later or apply security update 2015-001 for 10.8.x and 10.9.x versions. Please see the references for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT204244");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031650");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031521");
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

if((osVer == "10.9.5") || (osVer == "10.8.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.9.5" && version_is_less(version:buildVer, test_version:"13F34"))
  {
    fix = "Apply Security Update 2015-001";
    osVer = osVer + " Build " + buildVer;
  }

  else if(osVer == "10.8.5" && version_is_less(version:buildVer, test_version:"12F1107"))
  {
    fix = "Apply Security Update 2015-001";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.9")
{
  if(version_is_less(version:osVer, test_version:"10.9.5")){
    fix = "Upgrade to latest OS release 10.9.5 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.8")
{
  if(version_is_less(version:osVer, test_version:"10.8.5")){
    fix = "Upgrade to latest OS release 10.8.5 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.10")
{
  if(version_is_less(version:osVer, test_version:"10.10.2")){
    fix = "10.10.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);