###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1527_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for xmlrpc-c USN-1527-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1527-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.841137");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-11 09:38:28 +0530 (Tue, 11 Sep 2012)");
  script_cve_id("CVE-2012-0876", "CVE-2012-1148");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for xmlrpc-c USN-1527-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1527-2");
  script_tag(name:"affected", value:"xmlrpc-c on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1527-1 fixed vulnerabilities in Expat. This update provides the
  corresponding updates for XML-RPC for C and C++. Both issues described in the
  original advisory affected XML-RPC for C and C++ in Ubuntu 10.04 LTS, 11.04,
  11.10 and 12.04 LTS.

  Original advisory details:

  It was discovered that Expat computed hash values without restricting the
  ability to trigger hash collisions predictably. If a user or application
  linked against Expat were tricked into opening a crafted XML file, an attacker
  could cause a denial of service by consuming excessive CPU resources.
  (CVE-2012-0876)

  Tim Boddy discovered that Expat did not properly handle memory reallocation
  when processing XML files. If a user or application linked against Expat were
  tricked into opening a crafted XML file, an attacker could cause a denial of
  service by consuming excessive memory resources. This issue only affected
  Ubuntu 8.04 LTS, 10.04 LTS, 11.04 and 11.10. (CVE-2012-1148)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxmlrpc-core-c3", ver:"1.06.27-1ubuntu7.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxmlrpc-core-c3", ver:"1.16.33-3.1ubuntu5.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libxmlrpc-core-c3-0", ver:"1.16.32-0ubuntu4.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libxmlrpc-core-c3-0", ver:"1.16.32-0ubuntu3.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
