###############################################################################
# OpenVAS Vulnerability Test
#
# Apple MacOSX Security Updates(HT209446)-02
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814817");
  script_version("2019-05-22T13:05:41+0000");
  script_cve_id("CVE-2019-6219", "CVE-2019-6211", "CVE-2018-20346", "CVE-2018-20505",
                "CVE-2018-20506", "CVE-2019-6235");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-22 13:05:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-23 10:31:18 +0530 (Wed, 23 Jan 2019)");
  script_name("Apple MacOSX Security Updates(HT209446)-02");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - A denial of service issue which was addressed with improved validation.

  - A memory corruption issue which was addressed with improved state management.

  - Multiple memory corruption issues which were addressed with improved input
    validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service, execute arbitrary code and circumvent
  sandbox restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.14.x through 10.14.2");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209446");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.14");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer|| osVer !~ "^10\.14"|| "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.14",test_version2:"10.14.2"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.14.3");
  security_message(data:report);
  exit(0);
}

exit(99);