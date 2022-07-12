# OpenVAS Vulnerability Test
# $Id: deb_453_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 453-1
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
tag_insight = "Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical
security vulnerability in the memory management code of Linux inside
the mremap(2) system call.  Due to flushing the TLB (Translation
Lookaside Buffer, an address cache) too early it is possible for an
attacker to trigger a local root exploit.

The attack vectors for 2.4.x and 2.2.x kernels are exclusive for the
respective kernel series, though.  We formerly believed that the
exploitable vulnerability in 2.4.x does not exist in 2.2.x which is
still true.  However, it turned out that a second (sort of)
vulnerability is indeed exploitable in 2.2.x, but not in 2.4.x, with a
different exploit, of course.

For the stable distribution (woody) this problem has been fixed in
the following versions and architectures:

kernel-source-2.2.20                source    2.2.20-5woody3
kernel-image-2.2.20-i386            i386      2.2.20-5woody5
kernel-image-2.2.20-reiserfs-i386   i386      2.2.20-4woody1
kernel-image-2.2.20-amiga           m68k      2.20-4
kernel-image-2.2.20-atari           m68k      2.2.20-3
kernel-image-2.2.20-bvme6000        m68k      2.2.20-3
kernel-image-2.2.20-mac             m68k      2.2.20-3
kernel-image-2.2.20-mvme147         m68k      2.2.20-3
kernel-image-2.2.20-mvme16x         m68k      2.2.20-3
kernel-patch-2.2.20-powerpc         powerpc   2.2.20-3woody1

For the unstable distribution (sid) this problem will be fixed soon
for the architectures that still ship a 2.2.x kernel package.

We recommend that you upgrade your Linux kernel package.";
tag_summary = "The remote host is missing an update to kernel-source-2.2.20,
kernel-image-2.2.20-i386, kernel-image-2.2.20-reiserfs-i386,
kernel-image-2.2.20-amiga, kernel-image-2.2.20-atari,
kernel-image-2.2.20-bvme6000, kernel-image-2.2.20-mac,
kernel-image-2.2.20-mvme147, kernel-image-2.2.20-mvme16x,
kernel-patch-2.2.20-powerpc announced via advisory DSA 453-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20453-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302754");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(9686);
 script_cve_id("CVE-2004-0077");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 453-1 (kernel)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kernel-doc-2.2.20", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.2.20", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.2.20-powerpc", ver:"2.2.20-3woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.20", ver:"2.2.20-3woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.20-compact", ver:"2.2.20-5woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.20-idepci", ver:"2.2.20-5woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20", ver:"2.2.20-5woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-compact", ver:"2.2.20-5woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-idepci", ver:"2.2.20-5woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.20-reiserfs", ver:"2.2.20-4woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-reiserfs", ver:"2.2.20-4woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-amiga", ver:"2.2.20-4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-atari", ver:"2.2.20-3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-bvme6000", ver:"2.2.20-3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-mac", ver:"2.2.20-3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-mvme147", ver:"2.2.20-3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-mvme16x", ver:"2.2.20-3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-chrp", ver:"2.2.20-3woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-pmac", ver:"2.2.20-3woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.20-prep", ver:"2.2.20-3woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
