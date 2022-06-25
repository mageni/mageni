# OpenVAS Vulnerability Test
# $Id: deb_922_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 922-1
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
tag_insight = "Several local and remote vulnerabilities have been discovered in the
Linux kernel that may lead to a denial of service or the execution of
arbitrary code.  For details on the vulnerabilities addressed by
the missing update, please visit the referenced security advisories.

This update also contains a number of corrections for issues that
turned out to have no security implication afterwards.

The following matrix explains which kernel version for which architecture
fix the problems mentioned above:

Debian 3.1 (sarge)
Source                              2.6.8-16sarge1
Alpha architecture                  2.6.8-16sarge1
AMD64 architecture                  2.6.8-16sarge1
HP Precision architecture           2.6.8-6sarge1
Intel IA-32 architecture            2.6.8-16sarge1
Intel IA-64 architecture            2.6.8-14sarge1
Motorola 680x0 architecture         2.6.8-4sarge1
PowerPC architecture                2.6.8-12sarge1
IBM S/390 architecture              2.6.8-5sarge1
Sun Sparc architecture              2.6.8-15sarge1

We recommend that you upgrade your kernel package immediately and";
tag_summary = "The remote host is missing an update to kernel-source-2.4.27
announced via advisory DSA 922-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20922-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302783");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-2302", "CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1265", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1763", "CVE-2005-1765", "CVE-2005-1767", "CVE-2005-2456", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2548", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3105", "CVE-2005-3106", "CVE-2005-3107", "CVE-2005-3108", "CVE-2005-3109", "CVE-2005-3110", "CVE-2005-3271", "CVE-2005-3272", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");
 script_bugtraq_id(14477,15527,15528,15533);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 922-1 (kernel-source-2.4.27)");



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
if ((res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.6.8-s390", ver:"2.6.8-5sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-amd64-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-amd64-k8", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-amd64-k8-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-em64t-p4", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-em64t-p4-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-amd64-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-amd64-k8", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-amd64-k8-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-em64t-p4", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-em64t-p4-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-32", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-32-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-64", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-64-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-32", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-32-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-64", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-64-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-386", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-686", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-686-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-k7", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-k7-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-386", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-686", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-686-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-k7", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-k7-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-amiga", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-atari", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-bvme6000", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-hp", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mac", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme147", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme16x", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-q40", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-sun3", ver:"2.6.8-4sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-power3", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-power3-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-power4", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-power4-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-powerpc", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-powerpc-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-power3", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-power3-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-power4", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-power4-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-powerpc", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-powerpc-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-s390", ver:"2.6.8-5sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-s390-tape", ver:"2.6.8-5sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-s390x", ver:"2.6.8-5sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-2", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-sparc32", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-sparc64", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-sparc64-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-sparc32", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-sparc64", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-sparc64-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
