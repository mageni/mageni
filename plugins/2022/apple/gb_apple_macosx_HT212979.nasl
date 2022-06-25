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
  script_oid("1.3.6.1.4.1.25623.1.0.819822");
  script_version("2022-03-18T09:24:35+0000");
  script_cve_id("CVE-2021-30950", "CVE-2021-30931", "CVE-2021-30935", "CVE-2021-30942",
                "CVE-2021-30959", "CVE-2021-30961", "CVE-2021-30963", "CVE-2021-30958",
                "CVE-2021-30945", "CVE-2021-30977", "CVE-2021-30969", "CVE-2021-30939",
                "CVE-2021-30981", "CVE-2021-30982", "CVE-2021-30927", "CVE-2021-30980",
                "CVE-2021-30937", "CVE-2021-30949", "CVE-2021-30990", "CVE-2021-30976",
                "CVE-2021-30929", "CVE-2021-30979", "CVE-2021-30940", "CVE-2021-30941",
                "CVE-2021-30973", "CVE-2021-30971", "CVE-2021-30995", "CVE-2021-30968",
                "CVE-2021-30947", "CVE-2021-30946", "CVE-2021-30975", "CVE-2021-30767",
                "CVE-2021-30970", "CVE-2021-30965", "CVE-2021-30938");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-18 11:33:43 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-30 18:16:00 +0000 (Thu, 30 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-03-17 11:44:49 +0530 (Thu, 17 Mar 2022)");
  script_name("Apple MacOSX Security Update (HT212979)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An access control issue.

  - Multiple state management errors.

  - An improper input validation.

  - An improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, denial of service, privilege escalation
  and information disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.6.2.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.6.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212979");
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

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.6.1"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6.2");
  security_message(data:report);
  exit(0);
}
exit(99);
