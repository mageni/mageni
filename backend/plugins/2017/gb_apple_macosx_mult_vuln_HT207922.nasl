###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln_HT207922.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities-HT207922
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
  script_oid("1.3.6.1.4.1.25623.1.0.811536");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2017-7016", "CVE-2017-7033", "CVE-2017-7015", "CVE-2017-7050",
                "CVE-2017-7054", "CVE-2017-7062", "CVE-2017-7008", "CVE-2016-9586",
                "CVE-2016-9594", "CVE-2017-2629", "CVE-2017-7468", "CVE-2017-7014",
                "CVE-2017-7017", "CVE-2017-7035", "CVE-2017-7044", "CVE-2017-7036",
                "CVE-2017-7045", "CVE-2017-7025", "CVE-2017-7027", "CVE-2017-7069",
                "CVE-2017-7026", "CVE-2017-7068", "CVE-2017-9417");
  script_bugtraq_id(99882, 99883, 99880, 95019, 95094, 96382, 97962, 99482);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-20 12:23:38 +0530 (Thu, 20 Jul 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-HT207922");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A buffer overflow error.

  - Multiple input validation issues.

  - Multiple issues in curl.

  - An input validation issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, gain extra privileges and execute arbitrary code.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x before
  10.12.6");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207922");

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
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.6");
    security_message(data:report);
    exit(0);
  }
}

exit(99);