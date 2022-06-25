###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln_HT207797.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-HT207797
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810986");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2017-6988", "CVE-2017-6978", "CVE-2017-2502", "CVE-2017-2497",
                "CVE-2017-6981", "CVE-2017-6986", "CVE-2017-2503", "CVE-2017-2545",
                "CVE-2017-2494", "CVE-2017-2501", "CVE-2017-2507", "CVE-2017-2509",
                "CVE-2017-6987", "CVE-2017-2542", "CVE-2017-2543", "CVE-2017-6985",
                "CVE-2017-2534", "CVE-2017-6977", "CVE-2017-2513", "CVE-2017-2518",
                "CVE-2017-2520", "CVE-2017-2519", "CVE-2017-6983", "CVE-2017-6991");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-16 15:13:02 +0530 (Tue, 16 May 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-HT207797");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A certificate validation issue existed in EAP-TLS when a certificate
    changed.

  - Multiple memory corruption issues.

  - Multiple input validation issues.

  - A URL handling issue due to poor state management.

  - An issue existed within the path validation logic for symlinks.

  - A race condition due to poor locking mechanism.

  - An access issue due to poor sandbox restrictions.

  - A use after free issue due to poor state management.

  - A buffer overflow issue due to poor memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, gain extra privileges, execute arbitrary code,
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x before
  10.12.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207797");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.12");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName && osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.4"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.5");
    security_message(data:report);
    exit(0);
  }
}

exit(99);