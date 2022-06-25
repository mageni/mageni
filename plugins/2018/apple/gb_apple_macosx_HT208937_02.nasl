###############################################################################
# OpenVAS Vulnerability Test
#
# Apple MacOSX Security Updates(HT208937)-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.813635");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-4277", "CVE-2018-4289", "CVE-2018-4248", "CVE-2018-4283",
                "CVE-2018-4293", "CVE-2018-4268", "CVE-2018-4285");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-10 10:54:05 +0530 (Tue, 10 Jul 2018)");
  script_name("Apple MacOSX Security Updates(HT208937)-02");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A spoofing issue existed in the handling of URLs.

  - A vulnerable code which leads to information disclosure.

  - An out-of-bounds read issue due to improper input validation.

  - A cookie management issue.

  - A memory corruption issue due to poor memory handling.

  - A type confusion issue due to poor memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct address bar spoofing, obtain sensitive information,
  execute arbitrary code, escalate privileges and cause denial of service condition.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.13.x through 10.13.5.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.6 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208937");
  script_xref(name:"URL", value:"https://www.apple.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(version_is_less(version:osVer, test_version:"10.13.6"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.13.6");
  security_message(data:report);
  exit(0);
}

exit(99);