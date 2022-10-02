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
  script_oid("1.3.6.1.4.1.25623.1.0.826550");
  script_version("2022-09-26T10:10:50+0000");
  script_cve_id("CVE-2019-14899", "CVE-2019-20838", "CVE-2020-10002", "CVE-2020-10003",
                "CVE-2020-10004", "CVE-2020-10005", "CVE-2020-10006", "CVE-2020-10007",
                "CVE-2020-10008", "CVE-2020-10009", "CVE-2020-10010", "CVE-2020-10011",
                "CVE-2020-10012", "CVE-2020-10014", "CVE-2020-10015", "CVE-2020-10016",
                "CVE-2020-10017", "CVE-2020-10663", "CVE-2020-13434", "CVE-2020-13435",
                "CVE-2020-13524", "CVE-2020-13630", "CVE-2020-13631", "CVE-2020-14155",
                "CVE-2020-15358", "CVE-2020-27893", "CVE-2020-27894", "CVE-2020-27896",
                "CVE-2020-27897", "CVE-2020-27898", "CVE-2020-27899", "CVE-2020-27900",
                "CVE-2020-27901", "CVE-2020-27903", "CVE-2020-27904", "CVE-2020-27906",
                "CVE-2020-27907", "CVE-2020-27908", "CVE-2020-27909", "CVE-2020-27910",
                "CVE-2020-27911", "CVE-2020-27912", "CVE-2020-27914", "CVE-2020-27915",
                "CVE-2020-27916", "CVE-2020-27917", "CVE-2020-27918", "CVE-2020-27919",
                "CVE-2020-27920", "CVE-2020-27921", "CVE-2020-27922", "CVE-2020-27923",
                "CVE-2020-27924", "CVE-2020-27927", "CVE-2020-27930", "CVE-2020-27931",
                "CVE-2020-27932", "CVE-2020-27935", "CVE-2020-27937", "CVE-2020-27942",
                "CVE-2020-27945", "CVE-2020-27950", "CVE-2020-27952", "CVE-2020-29629",
                "CVE-2020-29639", "CVE-2020-9849", "CVE-2020-9876", "CVE-2020-9883",
                "CVE-2020-9897", "CVE-2020-9941", "CVE-2020-9942", "CVE-2020-9943",
                "CVE-2020-9944", "CVE-2020-9945", "CVE-2020-9947", "CVE-2020-9949",
                "CVE-2020-9950", "CVE-2020-9955", "CVE-2020-9956", "CVE-2020-9960",
                "CVE-2020-9962", "CVE-2020-9963", "CVE-2020-9965", "CVE-2020-9966",
                "CVE-2020-9967", "CVE-2020-9969", "CVE-2020-9971", "CVE-2020-9974",
                "CVE-2020-9975", "CVE-2020-9977", "CVE-2020-9978", "CVE-2020-9987",
                "CVE-2020-9988", "CVE-2020-9989", "CVE-2020-9991", "CVE-2020-9996",
                "CVE-2020-9999", "CVE-2021-1755", "CVE-2021-1775", "CVE-2021-1790",
                "CVE-2021-1803");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 19:16:00 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 23:16:40 +0530 (Thu, 22 Sep 2022)");
  script_name("Apple MacOSX Security Update(HT211931)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple integer overflows.

  - Multiple out-of-bounds read issues.

  - Multiple out-of-bounds write issues.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities allow remote attackers to execute arbitrary code, bypass
  security restrictions, disclose sensitive information and cause a denial of
  service on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur prior to
  version 11.0.1.");

  script_tag(name:"solution", value:"Upgrade to macOS Big Sur 11.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211931");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.0.1"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.0.1");
  security_message(data:report);
  exit(0);
}

exit(99);
