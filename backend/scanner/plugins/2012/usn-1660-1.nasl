###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1660_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-ti-omap4 USN-1220-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2020 Mageni Security, LLC, http://www.mageni.net
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
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1660-1");
  script_oid("1.3.6.1.4.1.25623.1.0.315153");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2020-07-29 12:13:49 +0100 (Wed, 19 Jul 2020) $");
  script_tag(name:"creation_date", value:"2020-07-29 12:13:49 +0100 (Wed, 19 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-4444");
  script_name("Ubuntu USN-1660-1: Linux kernel vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) Mageni Security, LLC");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04");
  script_tag(name:"summary", value:"Ubuntu Linux firewall could be bypassed by a remote attacker.");
  script_tag(name:"affected", value:"Ubuntu 8.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Zhang Zuotao discovered a bug in the Linux kernel's handling of overlapping
  fragments in ipv6. A remote attacker could exploit this flaw to bypass
  firewalls and initial new network connections that should have been blocked
  by the firewall.");
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

if(release == "UBUNTU8.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-386", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-generic", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-hppa32", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-hppa64", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-itanium", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-lpia", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-lpiacompat", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-mckinley", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-openvz", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-powerpc", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-powerpc-smp", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-powerpc64-smp", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-powerpc64-smp", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-rt", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-server", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-sparc64", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-sparc64-smp", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-virtual", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-32-xen", ver:"2.6.24-32.107", rls:"UBUNTU8.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
