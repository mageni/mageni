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
  script_oid("1.3.6.1.4.1.25623.1.0.826543");
  script_version("2022-09-26T10:10:50+0000");
  script_cve_id("CVE-2020-9846", "CVE-2021-30808", "CVE-2021-30809", "CVE-2021-30813",
                "CVE-2021-30814", "CVE-2021-30818", "CVE-2021-30821", "CVE-2021-30823",
                "CVE-2021-30824", "CVE-2021-30831", "CVE-2021-30833", "CVE-2021-30836",
                "CVE-2021-30840", "CVE-2021-30846", "CVE-2021-30848", "CVE-2021-30849",
                "CVE-2021-30851", "CVE-2021-30852", "CVE-2021-30861", "CVE-2021-30864",
                "CVE-2021-30866", "CVE-2021-30867", "CVE-2021-30868", "CVE-2021-30873",
                "CVE-2021-30874", "CVE-2021-30876", "CVE-2021-30877", "CVE-2021-30879",
                "CVE-2021-30880", "CVE-2021-30881", "CVE-2021-30883", "CVE-2021-30884",
                "CVE-2021-30886", "CVE-2021-30887", "CVE-2021-30888", "CVE-2021-30889",
                "CVE-2021-30890", "CVE-2021-30892", "CVE-2021-30895", "CVE-2021-30896",
                "CVE-2021-30897", "CVE-2021-30899", "CVE-2021-30901", "CVE-2021-30903",
                "CVE-2021-30904", "CVE-2021-30905", "CVE-2021-30906", "CVE-2021-30907",
                "CVE-2021-30908", "CVE-2021-30909", "CVE-2021-30910", "CVE-2021-30911",
                "CVE-2021-30912", "CVE-2021-30913", "CVE-2021-30915", "CVE-2021-30916",
                "CVE-2021-30917", "CVE-2021-30919", "CVE-2021-30920", "CVE-2021-30922",
                "CVE-2021-30923", "CVE-2021-30924", "CVE-2021-30930", "CVE-2021-30931",
                "CVE-2021-30933", "CVE-2021-30994", "CVE-2021-31002", "CVE-2021-31004",
                "CVE-2021-31005", "CVE-2021-31008", "CVE-2021-31011");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-02 15:41:00 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 23:16:40 +0530 (Thu, 22 Sep 2022)");
  script_name("Apple MacOSX Security Update(HT212869)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An out-of-bounds read was addressed with improved bounds checking.

  - A logic issue was addressed with improved state management.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities allow remote attackers to execute arbitrary code, bypass
  security restrictions, disclose sensitive information and cause a denial of
  service on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey 12.0.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 12.0.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212869");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^12\.");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName){
  exit(0);
}

if(osVer == "12.0")
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.0.1");
  security_message(data:report);
  exit(0);
}

exit(99);
