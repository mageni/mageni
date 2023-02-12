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
  script_oid("1.3.6.1.4.1.25623.1.0.826753");
  script_version("2023-01-11T10:12:37+0000");
  script_cve_id("CVE-2019-8748", "CVE-2019-11041", "CVE-2019-11042", "CVE-2019-8706",
                "CVE-2019-8850", "CVE-2019-8774", "CVE-2019-8753", "CVE-2019-8705",
                "CVE-2019-8592", "CVE-2019-8741", "CVE-2019-8825", "CVE-2019-8757",
                "CVE-2019-8736", "CVE-2019-8767", "CVE-2019-8737", "CVE-2019-8776",
                "CVE-2019-8509", "CVE-2019-8746", "CVE-2018-12152", "CVE-2018-12153",
                "CVE-2018-12154", "CVE-2019-8759", "CVE-2019-8758", "CVE-2019-8755",
                "CVE-2019-8703", "CVE-2019-8809", "CVE-2019-8744", "CVE-2019-8717",
                "CVE-2019-8709", "CVE-2019-8781", "CVE-2019-8749", "CVE-2019-8756",
                "CVE-2019-8750", "CVE-2019-8799", "CVE-2019-8826", "CVE-2019-8730",
                "CVE-2019-8772", "CVE-2019-8708", "CVE-2019-8715", "CVE-2019-8855",
                "CVE-2019-8770", "CVE-2019-8701", "CVE-2019-8761", "CVE-2019-8745",
                "CVE-2019-8831", "CVE-2019-8769", "CVE-2019-8768", "CVE-2019-8854");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-30 20:13:00 +0000 (Fri, 30 Oct 2020)");
  script_tag(name:"creation_date", value:"2023-01-10 15:43:23 +0530 (Tue, 10 Jan 2023)");
  script_name("Apple MacOSX Security Update(HT210634)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory corruption issues.

  - A resource exhaustion issue.

  - Multiple out-of-bounds read issues.

  - A user privacy issue.

  - A buffer overflow issue.

  - Multiple logic issues.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  allow remote attackers to execute arbitrary code, cause a denial of service
  and information disclosure on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions prior to 10.15.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Catalina 10.15
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210634");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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
if(!osVer || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"10.15"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.15");
  security_message(data:report);
  exit(0);
}
exit(0);
