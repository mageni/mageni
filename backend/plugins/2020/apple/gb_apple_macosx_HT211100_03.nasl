# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.816724");
  script_version("2020-03-29T02:34:12+0000");
  script_cve_id("CVE-2020-9785", "CVE-2020-9769", "CVE-2020-3889", "CVE-2020-3883",
                "CVE-2020-3881", "CVE-2019-19232", "CVE-2019-14615", "CVE-2020-3903",
                "CVE-2020-9776", "CVE-2020-9773", "CVE-2020-3913");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-30 09:58:56 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-26 12:25:20 +0530 (Thu, 26 Mar 2020)");
  script_name("Apple MacOSX Security Updates(HT211100)-03");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple memory corruption issues due to improper state management.

  - A logic issue due to improper state management.

  - An information disclosure issue due to improper state management.

  - A memory corruption issue due to improper memory handling.

  - A permissions issue existed due to improper permission validation.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code with kernel privileges, read arbitrary files and sensitive
  information and elevate privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.15.x through 10.15.3");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.15.4 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211100");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.3")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.15.4");
  security_message(port:0, data:report);
  exit(0);
}
exit(99);
