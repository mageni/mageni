###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Multiple Vulnerabilities-01 October-15
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2018-05-15
# For proper Version Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806148");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2015-5943", "CVE-2015-6983", "CVE-2015-7061", "CVE-2015-7060",
                "CVE-2015-7059", "CVE-2015-7007", "CVE-2015-5945", "CVE-2015-6563",
                "CVE-2014-3565", "CVE-2012-6151", "CVE-2015-7988", "CVE-2015-6994",
                "CVE-2015-6988", "CVE-2015-6974", "CVE-2015-7021", "CVE-2015-7020",
                "CVE-2015-7019", "CVE-2015-7008", "CVE-2015-6990", "CVE-2015-6987",
                "CVE-2015-6995", "CVE-2015-7017", "CVE-2015-7015", "CVE-2015-7023",
                "CVE-2015-7006", "CVE-2015-7003");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-29 12:54:16 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 October-15");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code, overwrite cookies, elevate privileges, execute
  arbitrary code with system privileges, cause unexpected application termination,
  read kernel memory, conduct impersonation attacks, run arbitrary AppleScript,
  overwrite arbitrary files and control keychain access prompts.");

  script_tag(name:"affected", value:"Apple OS X El Capitan versions before
  10.11.1");

  script_tag(name:"solution", value:"Upgrade Apple OS X El Capitan to version
  10.11.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205375");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.11");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(osVer && osVer =~ "^10\.11")
{

  if(version_is_less(version:osVer, test_version:"10.11.1"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11.1");
    security_message(data:report);
    exit(0);
  }
}

exit(99);