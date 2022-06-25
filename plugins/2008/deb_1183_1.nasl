# OpenVAS Vulnerability Test
# $Id: deb_1183_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1183-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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

include("revisions-lib.inc");
tag_insight = "Several security related problems have been discovered in the Linux
kernel which may lead to a denial of service or even the execution of
arbitrary code.  The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2005-4798

A buffer overflow in NFS readlink handling allows a malicious
remote server to cause a denial of service.

CVE-2006-2935

Diego Calleja Garcia discovered a buffer overflow in the DVD
handling code that could be exploited by a specially crafted DVD
or USB storage device to execute arbitrary code.

CVE-2006-1528

A bug in the SCSI driver allows a local user to cause a denial of
service.

CVE-2006-2444

Patrick McHardy discovered a bug in the SNMP NAT helper that
allows remote attackers to cause a denial of service.

CVE-2006-2446

A race condition in the socket buffer handling allows remote
attackers to cause a denial of service.

CVE-2006-3745

Wei Wang discovered a bug in the SCTP implementation that allows
local users to cause a denial of service and possibly gain root
privileges.

CVE-2006-4535

David Miller reported a problem with the fix for CVE-2006-3745
that allows local users to crash the system using via an SCTP
socket with a certain SO_LINGER value.


The following matrix explains which kernel version for which
architecture fixes the problem mentioned above:

stable (sarge)
Source                           2.4.27-10sarge4
Alpha architecture               2.4.27-10sarge4
ARM architecture                 2.4.27-2sarge4
Intel IA-32 architecture         2.4.27-10sarge4
Intel IA-64 architecture         2.4.27-10sarge4
Motorola 680x0 architecture      2.4.27-3sarge4
MIPS architectures               2.4.27-10.sarge4.040815-1
PowerPC architecture             2.4.27-10sarge4
IBM S/390                        2.4.27-2sarge4
Sun Sparc architecture           2.4.27-9sarge4
FAI                              1.9.1sarge4
mindi-kernel                     2.4.27-2sarge3
kernel-image-speakup-i386        2.4.27-1.1sarge3
systemimager                     3.2.3-6sarge3


For the unstable distribution (sid) these problems won't be fixed
anymore in the 2.4 kernel series.

We recommend that you upgrade your kernel package and reboot the";
tag_summary = "The remote host is missing an update to kernel-source-2.4.27
announced via advisory DSA 1183-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201183-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300597");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-4798", "CVE-2006-2935", "CVE-2006-1528", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-3745", "CVE-2006-4535");
 script_bugtraq_id(18081,18101,18847,19666,20087);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1183-1 (kernel-source-2.4.27)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-s390", ver:"2.4.27-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.27-speakup", ver:"2.4.27-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-i386-standard", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-boot-ia64-standard", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-client", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-common", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-doc", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server-flamethrowerd", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"systemimager-server", ver:"3.2.3-6sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-2", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-3", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-generic", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-generic", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-generic", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-generic", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bast", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-lart", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-netwinder", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscpc", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-riscstation", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-386", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-586tsc", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-686", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-686-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-k6", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-k7", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-k7-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-386", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-586tsc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-686", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-686-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k6", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k7", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-k7-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-386", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-586tsc", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-686", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-686-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-k6", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-k7", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-k7-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-386", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-586tsc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-686", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-686-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k6", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k7", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-k7-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-386", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-586tsc", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-686", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-686-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-k6", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-k7", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-2-k7-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-386", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-586tsc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-686", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-686-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k6", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k7", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.27-3-k7-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-speakup", ver:"2.4.27-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-speakup", ver:"2.4.27-1.1sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mindi-kernel", ver:"2.4.27-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-itanium", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-itanium-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-mckinley", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-mckinley-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-itanium", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-itanium-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-mckinley", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-mckinley-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-itanium-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4-mckinley-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-itanium", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-itanium-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-mckinley", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-mckinley-smp", ver:"2.4.27-10sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-itanium", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-itanium-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-mckinley", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-mckinley-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-amiga", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-atari", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-bvme6000", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mac", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme147", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-mvme16x", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-q40", ver:"2.4.27-3sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-ip22", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-ip22", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-sb1-swarm-bn", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r3k-kn02", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r4k-kn04", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-cobalt", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-r5k-lasat", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-xxs1500", ver:"2.4.27-10.sarge4.040815-1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-apus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-nubus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-small", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.4.27-powerpc-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-apus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-nubus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-powerpc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-apus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-nubus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-small", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-powerpc-smp", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-apus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-nubus", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.27-powerpc", ver:"2.4.27-10sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-s390", ver:"2.4.27-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-s390-tape", ver:"2.4.27-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-s390x", ver:"2.4.27-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390-tape", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-s390x", ver:"2.4.27-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-sparc32", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-sparc32-smp", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-sparc64", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-2-sparc64-smp", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc32", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc32-smp", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc64", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.27-3-sparc64-smp", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-sparc32", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-sparc32-smp", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-sparc64", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-2-sparc64-smp", ver:"2.4.27-9sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc32", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc32-smp", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc64", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.27-3-sparc64-smp", ver:"2.4.27-9sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
