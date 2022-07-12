###############################################################################
# OpenVAS Vulnerability Test
#
# Apple MacOSX Security Updates(HT209193)-06
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814426");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-4126", "CVE-2018-4408", "CVE-2018-4310", "CVE-2018-3646",
                "CVE-2018-4331", "CVE-2018-4406", "CVE-2018-4407", "CVE-2018-4401",
                "CVE-2018-4348", "CVE-2018-4346", "CVE-2017-12613", "CVE-2017-12618",
                "CVE-2018-4203", "CVE-2018-4308", "CVE-2018-4153", "CVE-2018-4326",
                "CVE-2018-4304", "CVE-2018-4341", "CVE-2018-4354", "CVE-2018-4412",
                "CVE-2018-4411", "CVE-2018-4395", "CVE-2018-4295", "CVE-2018-4393");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-02 10:56:30 +0530 (Fri, 02 Nov 2018)");
  script_name("Apple MacOSX Security Updates(HT209193)-06");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple memory corruption issues related to improper memory handling and
    input validation.

  - An access issue related to improper sandbox restrictions.

  - An information disclosure issue was addressed by flushing the L1 data cache
    at the virtual machine entry.

  - Multiple input validation errors.

  - An out-of-bounds read error related to improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  execute arbitrary code with system privileges, circumvent sandbox restrictions,
  perform a denial of service attack and also disclose sensitive information.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.12.x through
  10.12.6 before build 16G1618 and 10.13.x through 10.13.6 before build 17G3025.");

  script_tag(name:"solution", value:"Apply the appropriate security patch. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209193");
  script_xref(name:"URL", value:"https://www.apple.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.12.6")
  {
    if(version_is_less(version:buildVer, test_version:"16G1618"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer =~ "^10\.13")
{
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(version_is_less(version:buildVer, test_version:"17G3025"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);