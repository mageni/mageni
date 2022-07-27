###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Predefined Sandbox Profiles Security Bypass Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803223");
  script_version("2019-05-22T12:34:41+0000");
  script_cve_id("CVE-2011-1516", "CVE-2008-7303");
  script_bugtraq_id(50644, 50716);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 12:34:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2013-02-01 12:42:10 +0530 (Fri, 01 Feb 2013)");
  script_name("Apple Mac OS X Predefined Sandbox Profiles Security Bypass Vulnerability");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[5-7]\.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48980");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71284");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/apple-osx-sandbox-bypass");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain unauthorized
  access to restricted network resources through the use of Apple events.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.5.x through 10.7.2.");

  script_tag(name:"insight", value:"The kSBXProfileNoNetwork and kSBXProfileNoInternet sandbox
  profiles fails to propagate restrictions to all created processes, which allows remote attackers
  to access network resources via apple events to invoke the execution of other applications not
  directly restricted by the sandbox.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is installed with Apple Mac OS X operating system and
  is prone to a sandbox profiles security bypass vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(osVer =~ "^10\.[5-7]\." && version_in_range(version:osVer, test_version:"10.5.0", test_version2:"10.7.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"WillNotFix");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);