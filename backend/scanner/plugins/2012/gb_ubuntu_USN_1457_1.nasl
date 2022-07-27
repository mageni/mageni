###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1457_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux USN-1457-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1457-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841021");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-01 09:51:39 +0530 (Fri, 01 Jun 2012)");
  script_cve_id("CVE-2011-4131", "CVE-2012-1601", "CVE-2012-2121", "CVE-2012-2123",
                "CVE-2012-2133");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux USN-1457-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1457-1");
  script_tag(name:"affected", value:"linux on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Andy Adamson discovered a flaw in the Linux kernel's NFSv4 implementation.
  A remote NFS server (attacker) could exploit this flaw to cause a denial of
  service. (CVE-2011-4131)

  A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
  cpu setup. An unprivileged local user could exploit this flaw to crash the
  system leading to a denial of service. (CVE-2012-1601)

  A flaw was discovered in the Linux kernel's KVM (kernel virtual machine).
  An administrative user in the guest OS could leverage this flaw to cause a
  denial of service in the host OS. (CVE-2012-2121)

  Steve Grubb reported a flaw with Linux fscaps (file system base
  capabilities) when used to increase the permissions of a process. For
  application on which fscaps are in use a local attacker can disable address
  space randomization to make attacking the process with raised privileges
  easier. (CVE-2012-2123)

  Schacher Raindel discovered a flaw in the Linux kernel's memory handling
  when hugetlb is enabled. An unprivileged local attacker could exploit this
  flaw to cause a denial of service and potentially gain higher privileges.
  (CVE-2012-2133)");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-generic", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-generic-pae", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-omap", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-powerpc", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-powerpc-smp", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-powerpc64-smp", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-server", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-versatile", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-15-virtual", ver:"2.6.38-15.60", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
