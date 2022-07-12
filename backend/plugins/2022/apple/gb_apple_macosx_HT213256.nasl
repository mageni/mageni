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
  script_oid("1.3.6.1.4.1.25623.1.0.821248");
  script_version("2022-05-19T12:23:28+0000");
  script_cve_id("CVE-2018-25032", "CVE-2021-4136", "CVE-2021-4166", "CVE-2021-4173",
                "CVE-2021-4187", "CVE-2021-4192", "CVE-2021-4193", "CVE-2021-44224",
                "CVE-2021-44790", "CVE-2021-45444", "CVE-2021-46059", "CVE-2022-0128",
                "CVE-2022-0530", "CVE-2022-0778", "CVE-2022-22589", "CVE-2022-22663",
                "CVE-2022-22665", "CVE-2022-22674", "CVE-2022-22675", "CVE-2022-22719",
                "CVE-2022-22720", "CVE-2022-22721", "CVE-2022-23308", "CVE-2022-26697",
                "CVE-2022-26698", "CVE-2022-26706", "CVE-2022-26712", "CVE-2022-26714",
                "CVE-2022-26715", "CVE-2022-26718", "CVE-2022-26720", "CVE-2022-26721",
                "CVE-2022-26722", "CVE-2022-26723", "CVE-2022-26726", "CVE-2022-26728",
                "CVE-2022-26745", "CVE-2022-26746", "CVE-2022-26748", "CVE-2022-26751",
                "CVE-2022-26755", "CVE-2022-26756", "CVE-2022-26757", "CVE-2022-26761",
                "CVE-2022-26763", "CVE-2022-26766", "CVE-2022-26767", "CVE-2022-26768",
                "CVE-2022-26769", "CVE-2022-26770", "CVE-2022-26776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-20 09:52:18 +0000 (Fri, 20 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 16:22:00 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-05-19 11:15:30 +0530 (Thu, 19 May 2022)");
  script_name("Apple MacOSX Security Update (HT213256)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple memory corruption issues.

  - Multiple issues in apache.

  - Multiple out-of-bounds read issues.

  - Multiple out-of-bounds write issues.

  - Multiple use after free errors.

  - Multiple input validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, denial of service, privilege escalation
  and information disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.6.6.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.6.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213256");
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

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.6.5"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6.6");
  security_message(data:report);
  exit(0);
}
exit(99);
