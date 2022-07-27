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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814887");
  script_version("2019-05-22T13:43:48+0000");
  script_cve_id("CVE-2019-8568", "CVE-2019-8560", "CVE-2019-6237", "CVE-2019-8571",
                "CVE-2019-8583", "CVE-2019-8584", "CVE-2019-8586", "CVE-2019-8587",
                "CVE-2019-8594", "CVE-2019-8595", "CVE-2019-8596", "CVE-2019-8597",
                "CVE-2019-8601", "CVE-2019-8608", "CVE-2019-8609", "CVE-2019-8610",
                "CVE-2019-8611", "CVE-2019-8615", "CVE-2019-8619", "CVE-2019-8622",
                "CVE-2019-8623", "CVE-2019-8628", "CVE-2019-8600", "CVE-2019-8602",
                "CVE-2019-8607", "CVE-2019-8589", "CVE-2019-8585", "CVE-2019-8577",
                "CVE-2019-8576", "CVE-2019-8634", "CVE-2019-8635", "CVE-2019-8616",
                "CVE-2019-8598", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130",
                "CVE-2019-11091", "CVE-2019-8612");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 13:43:48 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-14 10:43:07 +0530 (Tue, 14 May 2019)");
  script_name("Apple MacOSX Security Updates (HT210119) - 01");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A validation issue in the handling of symlinks.

  - Multiple input validation issue with improper memory handling and
    input validation.

  - Multiple out-of-bounds read issues with improper input and bounds
    checking.

  - Multiple memory corruption issues addressed with improper input validation.

  - An authentication issue with improper state management.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to modify protected parts of the file system, read
  restricted memory or kernel memory, elevate privileges, execute arbitrary code
  with system privileges or cause denial of service.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.14.x through 10.14.4.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210119");

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
if(!osVer|| osVer !~ "^10\.14"|| "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.4"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.14.5");
  security_message(data:report);
  exit(0);
}
exit(99);
