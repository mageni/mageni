# OpenVAS Vulnerability Test
# $Id: deb_3170.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3170-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703170");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2013-7421", "CVE-2014-7822", "CVE-2014-8160", "CVE-2014-8559",
                  "CVE-2014-9585", "CVE-2014-9644", "CVE-2014-9683", "CVE-2015-0239",
                  "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-1593");
  script_name("Debian Security Advisory DSA 3170-1 (linux - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-23 00:00:00 +0100 (Mon, 23 Feb 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3170.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 3.2.65-1+deb7u2. Additionally this update
fixes regressions introduced in versions 3.2.65-1 and 3.2.65-1+deb7u1.

For the upcoming stable distribution (jessie), these problems will be fixed
soon (a subset is fixed already).

For the unstable distribution (sid), these problems will be fixed soon
(a subset is fixed already).

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in the Linux kernel that may lead to a denial of service, information
leaks or privilege escalation.

CVE-2013-7421 /
CVE-2014-9644
It was discovered that the Crypto API allowed unprivileged users
to load arbitrary kernel modules. A local user can use this flaw
to exploit vulnerabilities in modules that would not normally be
loaded.

CVE-2014-7822
Akira Fujita found that the splice() system call did not validate
the given file offset and length. A local unprivileged user can use
this flaw to cause filesystem corruption on ext4 filesystems, or
possibly other effects.

CVE-2014-8160
Florian Westphal discovered that a netfilter (iptables/ip6tables) rule
accepting packets to a specific SCTP, DCCP, GRE or UDPlite
port/endpoint could result in incorrect connection tracking state.
If only the generic connection tracking module (nf_conntrack) was
loaded, and not the protocol-specific connection tracking module,
this would allow access to any port/endpoint of the specified
protocol.

CVE-2014-8559
It was found that kernel functions that iterate over a directory
tree can dead-lock or live-lock in case some of the directory
entries were recently deleted or dropped from the cache. A local
unprivileged user can use this flaw for denial of service.

CVE-2014-9585
Andy Lutomirski discovered that address randomisation for the vDSO
in 64-bit processes is extremely biased. A local unprivileged user
could potentially use this flaw to bypass the ASLR protection
mechanism.

CVE-2014-9683
Dmitry Chernenkov discovered that eCryptfs writes past the end of
the allocated buffer during encrypted filename decoding, resulting
in local denial of service.

CVE-2015-0239
It was found that KVM did not correctly emulate the x86 SYSENTER
instruction. An unprivileged user within a guest system that has
not enabled SYSENTER, for example because the emulated CPU vendor
is AMD, could potentially use this flaw to cause a denial of
service or privilege escalation in that guest.

CVE-2015-1420
It was discovered that the open_by_handle_at() system call reads
the handle size from user memory a second time after validating
it. A local user with the CAP_DAC_READ_SEARCH capability could use
this flaw for privilege escalation.

CVE-2015-1421
It was found that the SCTP implementation could free an
authentication state while it was still in use, resulting in heap
corruption. This could allow remote users to cause a denial of
service or privilege escalation.

CVE-2015-1593
It was found that address randomisation for the initial stack in
64-bit processes was limited to 20 rather than 22 bits of entropy.
A local unprivileged user could potentially use this flaw to
bypass the ASLR protection mechanism.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-4kc-malta", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-5kc-malta", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-ia64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mips", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mipsel", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-powerpc", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-sparc", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-itanium", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-loongson-2f", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mckinley", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-octeon", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc-smp", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r4k-ip22", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-cobalt", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-ip32", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-s390x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1-bcm91250a", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1a-bcm91480b", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64-smp", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-4kc-malta", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-5kc-malta", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-itanium", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-loongson-2f", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mckinley", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-octeon", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc-smp", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r4k-ip22", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-cobalt", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-ip32", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-dbg", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-tape", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1-bcm91250a", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1a-bcm91480b", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64-smp", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.65-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}