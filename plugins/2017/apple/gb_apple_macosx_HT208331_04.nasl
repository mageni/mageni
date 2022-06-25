###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_HT208331_04.nasl 14295 2019-03-18 20:16:46Z cfischer $
#
# Apple MacOSX Security Updates(HT208331)-04
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812408");
  script_version("$Revision: 14295 $");
  script_cve_id("CVE-2017-13876", "CVE-2017-13875", "CVE-2017-13871", "CVE-2017-13860",
		"CVE-2017-13883", "CVE-2017-13848", "CVE-2017-13858", "CVE-2017-13878",
	        "CVE-2017-13865");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 21:16:46 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-12-07 10:51:33 +0530 (Thu, 07 Dec 2017)");
  script_name("Apple MacOSX Security Updates(HT208331)-04");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Security update resolves,

  - A memory corruption issue was addressed with improved memory handling.

  - An out-of-bounds read was addressed through improved bounds checking.

  - A logic error existed in the validation of credentials.

  - An inconsistent user interface issue was addressed with improved state management.

  - An input validation issue existed in the kernel.

  - An out-of-bounds read issue existed that led to the disclosure of kernel memory.

  - A validation issue was addressed with improved input sanitization.

  - An encryption issue existed with S/MIME credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code with kernel and system privileges. Also
  attacker may be able to bypass administrator authentication without supplying
  the administrator's password.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208331");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13" || "Mac OS X" >!< osName){
  exit(0);
}

if(osVer == "10.13.1")
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.13.2");
  security_message(data:report);
  exit(0);
}

exit(99);