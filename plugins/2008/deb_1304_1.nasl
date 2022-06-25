# OpenVAS Vulnerability Test
# $Id: deb_1304_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1304-1
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
tag_solution = "The following matrix explains which kernel version for which architecture
fix the problems mentioned above:

Debian 3.1 (sarge)
Source                      2.6.8-16sarge7
Alpha architecture          2.6.8-16sarge7
AMD64 architecture          2.6.8-16sarge7
HP Precision architecture   2.6.8-6sarge7
Intel IA-32 architecture    2.6.8-16sarge7
Intel IA-64 architecture    2.6.8-14sarge7
Motorola 680x0 architecture 2.6.8-4sarge7
PowerPC architecture        2.6.8-12sarge7
IBM S/390 architecture      2.6.8-5sarge7
Sun Sparc architecture      2.6.8-15sarge7

We recommend that you upgrade your kernel package immediately and reboot

https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201304-1";

tag_insight = "For details on the issues addressed with this update,
please visit the referenced security advisories.";
tag_summary = "The remote host is missing an update to kernel-source-2.6.8
announced via advisory DSA 1304-1.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301447");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-4811", "CVE-2006-4814", "CVE-2006-4623", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-6053", "CVE-2006-6056", "CVE-2006-6060", "CVE-2006-6106", "CVE-2006-6535", "CVE-2007-0958", "CVE-2007-1357", "CVE-2007-1592", "CVE-2004-1073");
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
 script_name("Debian Security Advisory DSA 1304-1 (kernel-source-2.6.8)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"kernel-patch-2.6.8-s390", ver:"2.6.8-5sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-generic", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-generic", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-amd64-generic", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-amd64-k8", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-amd64-k8-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-em64t-p4", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-em64t-p4-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-amd64-generic", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-amd64-k8", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-amd64-k8-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-em64t-p4", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-em64t-p4-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-32", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-32-smp", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-64", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-64-smp", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-32", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-32-smp", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-64", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-64-smp", ver:"2.6.8-6sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-386", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-586tsc", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-686", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-686-smp", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-k6", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-k7", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.4.27-3-k7-smp", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-386", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-686", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-686-smp", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-k7", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hostap-modules-2.6.8-4-k7-smp", ver:"0.3.7-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-386", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-686", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-686-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-k7", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-k7-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-386", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-686", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-686-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-k7", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-k7-smp", ver:"2.6.8-16sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-itanium", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-itanium-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-mckinley", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-mckinley-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-itanium", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-itanium-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-itanium", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-itanium-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-mckinley", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-mckinley-smp", ver:"2.6.8-14sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-amiga", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-atari", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-bvme6000", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-hp", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mac", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme147", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme16x", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-q40", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-sun3", ver:"2.6.8-4sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power3", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power3-smp", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power4", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power4-smp", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-powerpc", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-powerpc-smp", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power3", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power3-smp", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power4", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power4-smp", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-powerpc", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-powerpc-smp", ver:"2.6.8-12sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mol-modules-2.6.8-4-powerpc", ver:"0.9.70+2.6.8+12sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mol-modules-2.6.8-4-powerpc-smp", ver:"0.9.70+2.6.8+12sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-s390", ver:"2.6.8-5sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-s390-tape", ver:"2.6.8-5sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-s390x", ver:"2.6.8-5sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-build-2.6.8-4", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-sparc32", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-sparc64", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-sparc64-smp", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-sparc32", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-sparc64", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-sparc64-smp", ver:"2.6.8-15sarge7", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
