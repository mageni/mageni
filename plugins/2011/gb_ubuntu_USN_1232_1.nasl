###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1232_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for xorg-server USN-1232-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1232-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840780");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4818", "CVE-2010-4819", "CVE-2011-4028", "CVE-2011-4029");
  script_name("Ubuntu Update for xorg-server USN-1232-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.10|10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1232-1");
  script_tag(name:"affected", value:"xorg-server on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly execute arbitrary code
  with root privileges. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2010-4818)

  It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly read arbitrary data from
  the X server process. This issue only affected Ubuntu 10.04 LTS.
  (CVE-2010-4819)

  Vladz discovered that the X server incorrectly handled lock files. A local
  attacker could use this flaw to determine if a file existed or not.
  (CVE-2011-4028)

  Vladz discovered that the X server incorrectly handled setting lock file
  permissions. A local attacker could use this flaw to gain read permissions
  on arbitrary files and view sensitive information. (CVE-2011-4029)");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.9.0-0ubuntu7.5", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.7.6-2ubuntu7.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.10.1-1ubuntu1.3", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
