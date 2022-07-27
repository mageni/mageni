# OpenVAS Vulnerability Test
# $Id: deb_2153_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2153-1 (linux-2.6)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.68992");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-0435", "CVE-2010-3699", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4649", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0521");
  script_name("Debian Security Advisory DSA 2153-1 (linux-2.6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202153-1");
  script_tag(name:"insight", value:"CVE-2010-0435
Gleb Napatov reported an issue in the KVM subsystem that allows virtual
machines to cause a denial of service of the host machine.

CVE-2010-3699
Keir Fraser provided a fix for an issue in the Xen subsystem.

CVE-2010-4158
Dan Rosenberg discovered an issue in the socket filters subsystem.

CVE-2010-4162
Dan Rosenberg discovered an overflow issue in the block I/O subsystem.

CVE-2010-4163
Dan Rosenberg discovered an issue in the block I/O subsystem.

CVE-2010-4242
Alan Cox reported an issue in the Bluetooth subsystem.

CVE-2010-4243
Brad Spengler reported a denial-of-service issue in the kernel memory
accounting system.

CVE-2010-4248
Oleg Nesterov reported an issue in the POSIX CPU timers subsystem.

CVE-2010-4249
Vegard Nossum reported an issue with the UNIX socket garbage collector.

CVE-2010-4258
Nelson Elhage reported an issue in Linux oops handling.

CVE-2010-4342
Nelson Elhage reported an issue in the econet protocol.

CVE-2010-4346
Tavis Ormandy discovered an issue in the install_special_mapping routine
which allows local users to bypass the mmap_min_addr security restriction.

CVE-2010-4526
Eugene Teo reported a race condition in the Linux SCTP implementation.

CVE-2010-4527
Dan Rosenberg reported two issues in the OSS soundcard driver. Local users
with access to the device (members of group 'audio' on default Debian
installations) may contain access to sensitive kernel memory or cause a
buffer overflow.

CVE-2010-4529
Dan Rosenberg reported an issue in the Linux kernel IrDA socket
implementation on non-x86 architectures. Local users may be able to gain
access to sensitive kernel memory via a specially crafted IRLMP_ENUMDEVICES
getsockopt call.

CVE-2010-4565
Dan Rosenberg reported an issue in the Linux CAN protocol implementation.
Local users can obtain the address of a kernel heap object which might help
facilitate system exploitation.

CVE-2010-4649
Dan Carpenter reported an issue in the uverb handling of the InfiniBand
subsystem. A potential buffer overflow may allow local users to cause a
denial of service (memory corruption) by passing in a large cmd.ne value.

CVE-2010-4656
Kees Cook reported an issue in the driver for I/O-Warrior USB devices.
Local users with access to these devices maybe able to overrun kernel
buffers, resulting in a denial of service or privilege escalation.

CVE-2010-4668
Dan Rosenberg reported an issue in the block subsystem. A local user can
cause a denial of service (kernel panic) by submitting certain 0-length I/O
requests.

CVE-2011-0521
Dan Carpenter reported an issue in the DVB driver for AV7110 cards.  Local
users can pass a negative info->num value, corrupting kernel memory and
causing a denial of service.
For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-26lenny2.");
  script_tag(name:"summary", value:"The remote host is missing an update to linux-2.6
announced via advisory DSA 2153-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"26", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-486", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-4kc-malta", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-5kc-malta", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-686", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-686-bigmem", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-alpha", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-amd64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-arm", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-armel", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-hppa", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-i386", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-ia64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-mips", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-mipsel", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-s390", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-all-sparc", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-alpha-generic", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-alpha-legacy", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-alpha-smp", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-amd64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-common", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-common-openvz", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-common-vserver", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-common-xen", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-footbridge", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-iop32x", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-itanium", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-ixp4xx", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-mckinley", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-openvz-686", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-openvz-amd64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-orion5x", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-parisc", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-parisc-smp", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-parisc64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-parisc64-smp", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-powerpc-smp", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-powerpc64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-r4k-ip22", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-r5k-cobalt", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-r5k-ip32", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-s390", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-s390x", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-sb1-bcm91250a", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-sparc64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-sparc64-smp", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-versatile", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-686", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-686-bigmem", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-amd64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-itanium", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-mckinley", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-powerpc64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-s390x", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-vserver-sparc64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-xen-686", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-xen-amd64", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2-s390-tape", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"26-2", ver:"2.6.26-26lenny2", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}