# Copyright (C) 2023 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826796");
  script_version("2023-01-26T10:11:56+0000");
  script_cve_id("CVE-2022-32221", "CVE-2022-35260", "CVE-2022-3705", "CVE-2022-42915",
                "CVE-2022-42916", "CVE-2023-23493", "CVE-2023-23496", "CVE-2023-23497",
                "CVE-2023-23498", "CVE-2023-23499", "CVE-2023-23500", "CVE-2023-23501",
                "CVE-2023-23502", "CVE-2023-23503", "CVE-2023-23504", "CVE-2023-23505",
                "CVE-2023-23506", "CVE-2023-23507", "CVE-2023-23508", "CVE-2023-23510",
                "CVE-2023-23511", "CVE-2023-23512", "CVE-2023-23513", "CVE-2023-23517",
                "CVE-2023-23518", "CVE-2023-23519");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 12:04:06 +0530 (Wed, 25 Jan 2023)");
  script_name("Apple MacOSX Security Update (HT213605)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper checks.

  - A buffer overflow issue.

  - Multiple issues in curl.

  - Multiple memory handling errors.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, elevate privileges, disclose sensitive
  information and bypass security restriction on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.2.");

  script_tag(name:"solution", value:"Upgrade to version 13.2 for macOS Ventura 13.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213605");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.2"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.2");
  security_message(data:report);
  exit(0);
}

exit(99);
