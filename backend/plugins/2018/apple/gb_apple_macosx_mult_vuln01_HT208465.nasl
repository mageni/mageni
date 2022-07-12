###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-01 (HT208465)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812661");
  script_version("2019-04-29T05:39:50+0000");
  script_cve_id("CVE-2018-4096", "CVE-2018-4088", "CVE-2018-4089", "CVE-2018-4091",
                "CVE-2018-4093", "CVE-2018-4092", "CVE-2018-4090", "CVE-2017-8817");
  script_bugtraq_id(102057);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-29 05:39:50 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-01-24 10:37:13 +0530 (Wed, 24 Jan 2018)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 (HT208465)");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An out-of-bounds read issue existed in the curl.

  - A memory initialization issue within kernel.

  - A race condition within kernel.

  - A validation issue within kernel.

  - A sandbox access issue.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system, bypass sandbox restrictions and
  read restricted memory.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13.x prior to
  10.13.3");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.13.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208465");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13")
  exit(0);

if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.13.3");
  security_message(data:report);
  exit(0);
}

exit(99);