# Copyright (C) 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
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
  script_oid("1.3.6.1.4.1.25623.1.0.826953");
  script_version("2023-03-30T10:10:01+0000");
  script_cve_id("CVE-2022-43551", "CVE-2022-43552", "CVE-2023-0049", "CVE-2023-0051",
                "CVE-2023-0054", "CVE-2023-0288", "CVE-2023-0433", "CVE-2023-0512",
                "CVE-2023-23514", "CVE-2023-23523", "CVE-2023-23525", "CVE-2023-23526",
                "CVE-2023-23527", "CVE-2023-23532", "CVE-2023-23533", "CVE-2023-23534",
                "CVE-2023-23535", "CVE-2023-23537", "CVE-2023-23538", "CVE-2023-23542",
                "CVE-2023-23543", "CVE-2023-27928", "CVE-2023-27929", "CVE-2023-27931",
                "CVE-2023-27932", "CVE-2023-27933", "CVE-2023-27934", "CVE-2023-27935",
                "CVE-2023-27936", "CVE-2023-27937", "CVE-2023-27941", "CVE-2023-27942",
                "CVE-2023-27943", "CVE-2023-27944", "CVE-2023-27946", "CVE-2023-27949",
                "CVE-2023-27951", "CVE-2023-27952", "CVE-2023-27953", "CVE-2023-27954",
                "CVE-2023-27955", "CVE-2023-27956", "CVE-2023-27957", "CVE-2023-27958",
                "CVE-2023-27961", "CVE-2023-27962", "CVE-2023-27963", "CVE-2023-27965",
                "CVE-2023-27968", "CVE-2023-27969", "CVE-2023-28178", "CVE-2023-28180",
                "CVE-2023-28181", "CVE-2023-28182", "CVE-2023-28190", "CVE-2023-28192",
                "CVE-2023-28200");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-03-30 10:10:01 +0000 (Thu, 30 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 11:22:17 +0530 (Wed, 29 Mar 2023)");
  script_name("Apple MacOSX Security Update (HT213670)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory handling issues.

  - Multiple validation issues.

  - Multiple issues in curl.

  - Improper checks and vulnerable code.

  - Improper state management.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, escalate privileges, bypass security
  restrictions and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.3.");

  script_tag(name:"solution", value:"Upgrade to version 13.3 for macOS Ventura 13.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213670");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:osVer, test_version:"13.3"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.3");
  security_message(data:report);
  exit(0);
}

exit(99);
