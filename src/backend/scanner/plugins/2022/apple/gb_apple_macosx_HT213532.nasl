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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826741");
  script_version("2022-12-19T08:37:49+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-42843", "CVE-2022-42847", "CVE-2022-42865", "CVE-2022-42854",
                "CVE-2022-42853", "CVE-2022-42859", "CVE-2022-32942", "CVE-2022-46693",
                "CVE-2022-42864", "CVE-2022-46690", "CVE-2022-46697", "CVE-2022-42837",
                "CVE-2022-46689", "CVE-2022-46701", "CVE-2022-42842", "CVE-2022-42861",
                "CVE-2022-42845", "CVE-2022-32943", "CVE-2022-42840", "CVE-2022-42855",
                "CVE-2022-42862", "CVE-2022-24836", "CVE-2022-29181", "CVE-2022-46695",
                "CVE-2022-42866", "CVE-2022-42867", "CVE-2022-46691", "CVE-2022-46692",
                "CVE-2022-42852", "CVE-2022-46696", "CVE-2022-46700", "CVE-2022-46698",
                "CVE-2022-46699", "CVE-2022-42863", "CVE-2022-42856", "CVE-2022-42841");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-12-19 08:37:49 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 02:12:00 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-12-16 13:46:21 +0530 (Fri, 16 Dec 2022)");
  script_name("Apple MacOSX Security Update (HT213532)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper checks.

  - Improper data protection.

  - Multiple memory and state handling errors.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, spoofing attack, disclose sensitive
  information and bypass security restriction on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.1.");

  script_tag(name:"solution", value:"Upgrade to version 13.1 for macOS Ventura 13.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213532");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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

if(version_is_less(version:osVer, test_version:"13.1"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.1");
  security_message(data:report);
  exit(0);
}

exit(99);
