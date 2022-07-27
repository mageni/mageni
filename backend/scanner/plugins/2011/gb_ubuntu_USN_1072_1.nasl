###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1072_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux vulnerabilities USN-1072-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1072-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840594");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_cve_id("CVE-2010-0435", "CVE-2010-2943", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3448", "CVE-2010-3698", "CVE-2010-3699", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3873", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4072", "CVE-2010-4074", "CVE-2010-4078", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160", "CVE-2010-4248");
  script_name("Ubuntu Update for linux vulnerabilities USN-1072-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1072-1");
  script_tag(name:"affected", value:"linux vulnerabilities on Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Gleb Napatov discovered that KVM did not correctly check certain privileged
  operations. A local attacker with access to a guest kernel could exploit
  this to crash the host system, leading to a denial of service.
  (CVE-2010-0435)

  Dave Chinner discovered that the XFS filesystem did not correctly order
  inode lookups when exported by NFS. A remote attacker could exploit this to
  read or write disk blocks that had changed file assignment or had become
  unlinked, leading to a loss of privacy. (CVE-2010-2943)

  Dan Rosenberg discovered that several network ioctls did not clear kernel
  memory correctly. A local user could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-3296, CVE-2010-3297)

  Dan Jacobson discovered that ThinkPad video output was not correctly
  access controlled. A local attacker could exploit this to hang the system,
  leading to a denial of service. (CVE-2010-3448)

  It was discovered that KVM did not correctly initialize certain CPU
  registers. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2010-3698)

  It was discovered that Xen did not correctly clean up threads. A local
  attacker in a guest system could exploit this to exhaust host system
  resources, leading to a denial of service. (CVE-2010-3699)

  Brad Spengler discovered that stack memory for new a process was not
  correctly calculated. A local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-3858)

  Dan Rosenberg discovered that the Linux kernel TIPC implementation
  contained multiple integer signedness errors. A local attacker could
  exploit this to gain root privileges. (CVE-2010-3859)

  Dan Rosenberg discovered that the Linux kernel X.25 implementation
  incorrectly parsed facilities. A remote attacker could exploit this to
  crash the kernel, leading to a denial of service. (CVE-2010-3873)

  Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
  not correctly clear kernel memory. A local attacker could exploit this to
  read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

  Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
  not properly initialize certain structures. A local attacker could exploit
  this to read kernel stack memory, leading to a loss of privacy.
  (CVE-2010-3876)

  Vasiliy Kulikov discovered that the TIPC interface did not correctly
  initialize certain structures. A local attacker could exploit this to
  read kernel stack memory, leading to a l ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-386", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-generic", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-openvz", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-rt", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-server", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-virtual", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28-xen", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-386", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-generic", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-openvz", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-rt", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-server", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-virtual", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-28-xen", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-28-386", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-28-generic", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-28-server", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug-2.6.24-28-virtual", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc-2.6.24", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-28", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source-2.6.24", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"acpi-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"acpi-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"block-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crypto-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-core-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fs-secondary-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ide-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ide-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipv6-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipv6-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"message-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pata-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"socket-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"socket-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"storage-core-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.24-28-386-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.24-28-generic-di", ver:"2.6.24-28.86", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
