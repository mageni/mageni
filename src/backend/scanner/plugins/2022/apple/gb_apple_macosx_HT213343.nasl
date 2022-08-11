# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821278");
  script_version("2022-07-28T10:10:25+0000");
  script_cve_id("CVE-2021-4136", "CVE-2021-4166", "CVE-2021-4173", "CVE-2021-4187",
                "CVE-2021-4192", "CVE-2021-4193", "CVE-2021-46059", "CVE-2022-0128",
                "CVE-2022-26704", "CVE-2022-32781", "CVE-2022-32785", "CVE-2022-32786",
                "CVE-2022-32787", "CVE-2022-32797", "CVE-2022-32799", "CVE-2022-32800",
                "CVE-2022-32805", "CVE-2022-32807", "CVE-2022-32811", "CVE-2022-32812",
                "CVE-2022-32813", "CVE-2022-32815", "CVE-2022-32819", "CVE-2022-32820",
                "CVE-2022-32823", "CVE-2022-32826", "CVE-2022-32831", "CVE-2022-32832",
                "CVE-2022-32834", "CVE-2022-32838", "CVE-2022-32839", "CVE-2022-32842",
                "CVE-2022-32843", "CVE-2022-32847", "CVE-2022-32849", "CVE-2022-32851",
                "CVE-2022-32853", "CVE-2022-32857");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-28 10:10:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-27 19:46:00 +0000 (Mon, 27 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-07-22 14:48:43 +0530 (Fri, 22 Jul 2022)");
  script_name("Apple MacOSX Security Update (HT213343)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - Multiple input validation errors.

  - Multiple issues in Vim.

  - Multiple issues in state management.

  - Multiple bounds checking issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, gain elevated privileges and bypass security
  restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X 10.15.x prior to
  Security Update 2022-005 Catalina.");

  script_tag(name:"solution", value:"Apply Security Update 2022-005 Catalina for
  10.15.x, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213343");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15\." || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.15")
{
  if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.6")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.15.7")
  {
    if(version_is_less(version:buildVer, test_version:"19H2026"))
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
