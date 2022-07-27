# OpenVAS Vulnerability Test
# $Id: deb_2469_1.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2469-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892469");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2012-2133", "CVE-2012-1601", "CVE-2012-0879", "CVE-2011-4086", "CVE-2012-2123");
  script_name("Debian Security Advisory DSA 2469-1 (linux-2.6 - privilege escalation/denial of service)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2012/dsa-2469.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"linux-2.6 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), this problem has been fixed in version
2.6.32-44. Updates are currently only available for the amd64, i386 and sparc
ports.

Note: updated linux-2.6 packages will also be made available in the release
of Debian 6.0.5, scheduled to take place the weekend of 2012.05.12. This
pending update will be version 2.6.32-45, and provides an additional fix for
build failures on some architectures. Users for whom this update is not
critical, and who may wish to avoid multiple reboots, should consider waiting
for the 6.0.5 release before updating, or installing the 2.6.32-45 version
ahead of time from proposed-updates.

The following matrix lists additional source packages that were rebuilt for
compatibility with or to take advantage of this update:

 Debian 6.0 (squeeze)user-mode-linux2.6.32-1um-4+44We recommend that you upgrade your linux-2.6 and user-mode-linux packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead
to a denial of service or privilege escalation. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2011-4086Eric Sandeen reported an issue in the journaling layer for ext4 filesystems
(jbd2). Local users can cause buffers to be accessed after they have been
torn down, resulting in a denial of service (DoS) due to a system crash.

CVE-2012-0879Louis Rilling reported two reference counting issues in the CLONE_IO
feature of the kernel. Local users can prevent io context structures
from being freed, resulting in a denial of service.

CVE-2012-1601Michael Ellerman reported an issue in the KVM subsystem. Local users could
cause a denial of service (NULL pointer dereference) by creating VCPUs
before a call to KVM_CREATE_IRQCHIP.

CVE-2012-2123Steve Grubb reported an issue in fcaps, a filesystem-based capabilities
system. Personality flags set using this mechanism, such as the disabling
of address space randomization, may persist across suid calls.

CVE-2012-2133Shachar Raindel discovered a use-after-free bug in the hugepages
quota implementation. Local users with permission to use hugepages
via the hugetlbfs implementation may be able to cause a denial of
service (system crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"firmware-linux-free", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-base", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-doc-2.6.32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-486", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-4kc-malta", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-5kc-malta", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686-bigmem", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-armel", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-i386", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-ia64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-mips", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-mipsel", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-powerpc", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-s390", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-sparc", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-openvz", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-vserver", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-xen", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-iop32x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-itanium", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-ixp4xx", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-kirkwood", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-mckinley", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-orion5x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc-smp", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r4k-ip22", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r5k-cobalt", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r5k-ip32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-s390x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sb1-bcm91250a", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sb1a-bcm91480b", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sparc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sparc64-smp", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-versatile", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-itanium", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-mckinley", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-powerpc", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-powerpc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-s390x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-sparc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-486", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-4kc-malta", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-5kc-malta", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-iop32x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-itanium", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-ixp4xx", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-kirkwood", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-mckinley", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-orion5x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc-smp", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r4k-ip22", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r5k-cobalt", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r5k-ip32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-s390x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-s390x-tape", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sb1-bcm91250a", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sb1a-bcm91480b", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sparc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sparc64-smp", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-versatile", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-itanium", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-mckinley", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-powerpc", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-powerpc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-s390x", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-sparc64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64-dbg", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-manual-2.6.32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-source-2.6.32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-support-2.6.32-5", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"linux-tools-2.6.32", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-686", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-amd64", ver:"2.6.32-44", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}