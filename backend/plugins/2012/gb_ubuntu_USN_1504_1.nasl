###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1504_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for qt4-x11 USN-1504-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1504-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841082");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-16 11:53:40 +0530 (Mon, 16 Jul 2012)");
  script_cve_id("CVE-2010-5076", "CVE-2011-3193", "CVE-2011-3194");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for qt4-x11 USN-1504-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1504-1");
  script_tag(name:"affected", value:"qt4-x11 on Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that Qt did not properly handle wildcard domain names or
  IP addresses in the Common Name field of X.509 certificates. An attacker
  could exploit this to perform a man in the middle attack to view sensitive
  information or alter encrypted communications. This issue only affected
  Ubuntu 10.04 LTS. (CVE-2010-5076)

  A heap-based buffer overflow was discovered in the HarfBuzz module. If a
  user were tricked into opening a crafted font file in a Qt application,
  an attacker could cause a denial of service or possibly execute arbitrary
  code with the privileges of the user invoking the program. (CVE-2011-3193)

  It was discovered that Qt did not properly handle greyscale TIFF images.
  If a Qt application could be made to process a crafted TIFF file, an
  attacker could cause a denial of service. (CVE-2011-3194)");
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

  if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4.6.2-0ubuntu5.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqtgui4", ver:"4.6.2-0ubuntu5.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libqt4-network", ver:"4.7.2-0ubuntu6.4", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libqtgui4", ver:"4.7.2-0ubuntu6.4", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
