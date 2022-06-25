###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1071_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-source-2.6.15 vulnerabilities USN-1071-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1071-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840595");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-3086", "CVE-2010-3859", "CVE-2010-3873", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-4078", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160");
  script_name("Ubuntu Update for linux-source-2.6.15 vulnerabilities USN-1071-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1071-1");
  script_tag(name:"affected", value:"linux-source-2.6.15 vulnerabilities on Ubuntu 6.06 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Tavis Ormandy discovered that the Linux kernel did not properly implement
  exception fixup. A local attacker could exploit this to crash the kernel,
  leading to a denial of service. (CVE-2010-3086)

  Dan Rosenberg discovered that the Linux kernel TIPC implementation
  contained multiple integer signedness errors. A local attacker could
  exploit this to gain root privileges. (CVE-2010-3859)

  Dan Rosenberg discovered that the Linux kernel X.25 implementation
  incorrectly parsed facilities. A remote attacker could exploit this to
  crash the kernel, leading to a denial of service. (CVE-2010-3873)

  Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
  not correctly clear kernel memory. A local attacker could exploit this to
  read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

  Vasiliy Kulikov discovered that the Linux kernel sockets implementation
  did not properly initialize certain structures. A local attacker could
  exploit this to read kernel stack memory, leading to a loss of privacy.
  (CVE-2010-3876)

  Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
  properly audit certain bytecodes in netlink messages. A local attacker
  could exploit this to cause the kernel to hang, leading to a denial of
  service. (CVE-2010-3880)

  Dan Rosenberg discovered that the SiS video driver did not correctly clear
  kernel memory. A local attacker could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-4078)

  Dan Rosenberg discovered that the RME Hammerfall DSP audio interface driver
  did not correctly clear kernel memory. A local attacker could exploit this
  to read kernel stack memory, leading to a loss of privacy. (CVE-2010-4080,
  CVE-2010-4081)

  Dan Rosenberg discovered that the semctl syscall did not correctly clear
  kernel memory. A local attacker could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-4083)

  James Bottomley discovered that the ICP vortex storage array controller
  driver did not validate certain sizes. A local attacker on a 64bit system
  could exploit this to crash the kernel, leading to a denial of service.
  (CVE-2010-4157)

  Dan Rosenberg discovered that the Linux kernel L2TP implementation
  contained multiple integer signedness errors. A local attacker could
  exploit this to to crash the kernel, or possibly gain root privileges.
  (CVE-2010-4160)");
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

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-55-386", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-55-686", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-55-k7", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-55-server-bigiron", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-55-server", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.15-55", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-55-386", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-55-686", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-55-k7", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-55-server-bigiron", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.15-55-server", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc-2.6.15", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source-2.6.15", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"acpi-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"cdrom-core-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"cdrom-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"crc-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ext2-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ext3-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fat-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fb-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firewire-core-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"floppy-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ide-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"input-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ipv6-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"irda-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"jfs-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"kernel-image-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"loop-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"md-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nfs-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-firmware-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-shared-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nic-usb-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ntfs-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"parport-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"plip-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ppp-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"reiserfs-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"sata-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-core-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"scsi-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"serial-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"socket-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ufs-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"usb-storage-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xfs-modules-2.6.15-55-386-di", ver:"2.6.15-55.93", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
