###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1111_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-source-2.6.15 USN-1111-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1111-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840638");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-4164", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4527", "CVE-2010-4529", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-1017");
  script_name("Ubuntu Update for linux-source-2.6.15 USN-1111-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1111-1");
  script_tag(name:"affected", value:"linux-source-2.6.15 on Ubuntu 6.06 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing. If
  a system was using X.25, a remote attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-4164)

  Vegard Nossum discovered that memory garbage collection was not handled
  correctly for active sockets. A local attacker could exploit this to
  allocate all available kernel memory, leading to a denial of service.
  (CVE-2010-4249)

  Nelson Elhage discovered that the kernel did not correctly handle process
  cleanup after triggering a recoverable kernel bug. If a local attacker were
  able to trigger certain kinds of kernel bugs, they could create a specially
  crafted process to gain root privileges. (CVE-2010-4258)

  Nelson Elhage discovered that Econet did not correctly handle AUN packets
  over UDP. A local attacker could send specially crafted traffic to crash
  the system, leading to a denial of service. (CVE-2010-4342)

  Dan Rosenberg discovered that the OSS subsystem did not handle name
  termination correctly. A local attacker could exploit this crash the system
  or gain root privileges. (CVE-2010-4527)

  Dan Rosenberg discovered that IRDA did not correctly check the size of
  buffers. On non-x86 systems, a local attacker could exploit this to read
  kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

  Dan Carpenter discovered that the TTPCI DVB driver did not check certain
  values during an ioctl. If the dvb-ttpci module was loaded, a local
  attacker could exploit this to crash the system, leading to a denial of
  service, or possibly gain root privileges. (CVE-2011-0521)

  Jens Kuehnel discovered that the InfiniBand driver contained a race
  condition. On systems using InfiniBand, a local attacker could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2011-0695)

  Timo Warns discovered that the LDM disk partition handling code did not
  correctly handle certain values. By inserting a specially crafted disk
  device, a local attacker could exploit this to gain root privileges.
  (CVE-2011-1017)");
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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-386", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-686", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-amd64-generic", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-amd64-k8", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-amd64-server", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-amd64-xeon", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-hppa32", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-hppa32-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-hppa64", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-hppa64-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-itanium", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-itanium-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-k7", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-mckinley", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-mckinley-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-powerpc", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-powerpc-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-powerpc64-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-server", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-server-bigiron", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-sparc64", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-57-sparc64-smp", ver:"2.6.15-57.97", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
