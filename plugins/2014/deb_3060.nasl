# OpenVAS Vulnerability Test
# $Id: deb_3060.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 3060-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703060");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-7207");
  script_name("Debian Security Advisory DSA 3060-1 (linux - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-31 00:00:00 +0100 (Fri, 31 Oct 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3060.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 3.2.63-2+deb7u1.

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service:

CVE-2014-3610
Lars Bull of Google and Nadav Amit reported a flaw in how KVM
handles noncanonical writes to certain MSR registers. A privileged
guest user can exploit this flaw to cause a denial of service
(kernel panic) on the host.

CVE-2014-3611
Lars Bull of Google reported a race condition in in the PIT
emulation code in KVM. A local guest user with access to PIT i/o
ports could exploit this flaw to cause a denial of service (crash)
on the host.

CVE-2014-3645 / CVE-2014-3646
The Advanced Threat Research team at Intel Security discovered
that the KVM subsystem did not handle the VM exits gracefully
for the invept (Invalidate Translations Derived from EPT) and
invvpid (Invalidate Translations Based on VPID) instructions. On
hosts with an Intel processor and invept/invppid VM exit
support, an unprivileged guest user could use these instructions
to crash the guest.

CVE-2014-3647
Nadav Amit reported that KVM mishandles noncanonical addresses when
emulating instructions that change rip, potentially causing a failed
VM-entry. A guest user with access to I/O or the MMIO can use this
flaw to cause a denial of service (system crash) of the guest.

CVE-2014-3673
Liu Wei of Red Hat discovered a flaw in net/core/skbuff.c leading to
a kernel panic when receiving malformed ASCONF chunks. A remote
attacker could use this flaw to crash the system.

CVE-2014-3687
A flaw in the sctp stack was discovered leading to a kernel panic
when receiving duplicate ASCONF chunks. A remote attacker could use
this flaw to crash the system.

CVE-2014-3688
It was found that the sctp stack is prone to a remotely triggerable
memory pressure issue caused by excessive queueing. A remote
attacker could use this flaw to cause denial-of-service conditions
on the system.

CVE-2014-3690
Andy Lutomirski discovered that incorrect register handling in KVM
may lead to denial of service.

CVE-2014-7207
Several Debian developers reported an issue in the IPv6 networking
subsystem. A local user with access to tun or macvtap devices, or a
virtual machine connected to such a device, can cause a denial of
service (system crash).

This update includes a bug fix related to CVE-2014-7207
that disables
UFO (UDP Fragmentation Offload) in the macvtap, tun, and virtio_net
drivers. This will cause migration of a running VM from a host running
an earlier kernel version to a host running this kernel version to fail,
if the VM has been assigned a virtio network device. In order to migrate
such a VM, it must be shut down first.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dasd-extra-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dasd-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fancontrol-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hypervisor-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ide-core-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ide-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-tape-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"leds-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-4kc-malta", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-5kc-malta", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-ia64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mips", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mipsel", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-powerpc", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-sparc", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-itanium", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-loongson-2f", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mckinley", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-octeon", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc-smp", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r4k-ip22", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-cobalt", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-ip32", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-s390x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1-bcm91250a", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1a-bcm91480b", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64-smp", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-4kc-malta", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-5kc-malta", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-itanium", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-loongson-2f", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mckinley", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-octeon", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc-smp", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r4k-ip22", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-cobalt", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-ip32", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-dbg", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-tape", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1-bcm91250a", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1a-bcm91480b", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64-smp", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mtd-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rtc-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sn-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-kirkwood-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-mx5-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-vexpress-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-s390x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-486-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-4kc-malta-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-686-pae-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-amd64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-iop32x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-itanium-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-loongson-2f-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-orion5x-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-powerpc-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sparc64-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-versatile-di", ver:"3.2.63-2+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}