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
  script_oid("1.3.6.1.4.1.25623.1.0.819819");
  script_version("2022-03-18T09:01:15+0000");
  script_cve_id("CVE-2022-22633", "CVE-2022-22631", "CVE-2022-22648", "CVE-2022-22627",
                "CVE-2022-22626", "CVE-2022-22625", "CVE-2022-22597", "CVE-2022-22616",
                "CVE-2022-22661", "CVE-2022-22613", "CVE-2022-22614", "CVE-2022-22615",
                "CVE-2022-22638", "CVE-2022-22632", "CVE-2022-22647", "CVE-2022-22656",
                "CVE-2022-22617", "CVE-2022-22650", "CVE-2022-22599", "CVE-2022-22662",
                "CVE-2022-22582");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-18 11:33:43 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-17 11:44:49 +0530 (Thu, 17 Mar 2022)");
  script_name("Apple MacOSX Security Update (HT213184)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A validation issue existed in the handling of symlinks.

  - Multiple state management errors.

  - An improper input validation.

  - An improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, denial of service, privilege escalation
  and information disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.6.5.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.6.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213184");
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
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.6.4"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6.5");
  security_message(data:report);
  exit(0);
}
exit(99);
