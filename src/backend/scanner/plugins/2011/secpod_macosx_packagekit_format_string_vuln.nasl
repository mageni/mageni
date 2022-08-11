###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X PackageKit Format String Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902715");
  script_version("2019-05-22T12:34:41+0000");
  script_cve_id("CVE-2010-4013");
  script_bugtraq_id(45693);
  script_tag(name:"last_modification", value:"2019-05-22 12:34:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2011-08-23 07:05:00 +0200 (Tue, 23 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apple Mac OS X PackageKit Format String Vulnerability");
  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4498");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42841");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024938");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Jan/msg00000.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause an unexpected
  application termination or arbitrary code execution.");

  script_tag(name:"affected", value:"Mac OS X version 10.6 through 10.6.5

  Mac OS X Server version 10.6 through 10.6.5.");

  script_tag(name:"insight", value:"The flaw is due to a format string error in PackageKit's handling of
  distribution scripts. A man-in-the-middle attacker may be able to cause an unexpected application termination
  or arbitrary code execution when the Software Update checks for new updates.");

  script_tag(name:"solution", value:"Upgrade to Mac OS X/Server version 10.6.6 or later.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.6 Update.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(osVer =~ "^10\.6\." && version_in_range(version:osVer, test_version:"10.6.0", test_version2:"10.6.5")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.6.6");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);