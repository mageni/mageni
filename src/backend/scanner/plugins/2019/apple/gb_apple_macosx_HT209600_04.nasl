# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815009");
  script_version("2019-05-22T13:43:48+0000");
  script_cve_id("CVE-2019-8502", "CVE-2019-8546", "CVE-2019-8545", "CVE-2019-8542",
                "CVE-2019-8549", "CVE-2019-6237", "CVE-2019-6239", "CVE-2019-7293",
                "CVE-2019-8565", "CVE-2019-8519", "CVE-2019-8533", "CVE-2019-8511",
                "CVE-2019-8514", "CVE-2019-8517", "CVE-2019-8516", "CVE-2019-8537",
                "CVE-2019-8550", "CVE-2019-8552", "CVE-2019-8507");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 13:43:48 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-26 15:43:30 +0530 (Tue, 26 Mar 2019)");
  script_name("Apple MacOSX Security Updates(HT209600)-04");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An API issue existed in the handling of dictation requests.

  - An access issue related to sandbox restrictions.

  - A memory corruption issue related to improper state management.

  - A buffer overflow error improper bounds checking.

  - Multiple input validation issues existed in MIG generated code.

  - An out-of-bounds read related to improper bounds checking.

  - This issue related to improper handling of file metadata.

  - A memory corruption issue related to improper memory handling.

  - A race condition was addressed with additional validation.

  - A lock handling issue related to improper lock handling.

  - A buffer overflow issue related to improper memory handling.

  - A logic issue was addressed with improved state management.

  - A validation issue was addressed with improved logic.

  - An access issue was addressed with improved memory management.

  - An issue existed in the pausing of FaceTime video.

  - A memory initialization issue was addressed with improved memory handling.

  - Multiple memory corruption issues related to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to view sensitive user information, elevate privileges, cause unexpected system
  termination and execute arbitrary code.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.14.x through 10.14.3.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209600");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.14");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.14" || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.14",test_version2:"10.14.3"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.14.4");
  security_message(data:report);
  exit(0);
}
exit(99);
