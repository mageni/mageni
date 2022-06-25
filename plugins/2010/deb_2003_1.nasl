# OpenVAS Vulnerability Test
# $Id: deb_2003_1.nasl 8250 2017-12-27 07:29:15Z teissa $
# Description: Auto-generated from advisory DSA 2003-1 (linux-2.6)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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

include("revisions-lib.inc");
tag_insight = "NOTE: This kernel update marks the final planned kernel security
update for the 2.6.18 kernel in the Debian release 'etch'.
Although security support for 'etch' officially ended on
Feburary 15th, 2010, this update was already in preparation
before that date.  A final update that includes fixes for these
issues in the 2.6.24 kernel is also in preparation and will be
released shortly.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. For details,
please visit the referenced security advisories.

This update also fixes a regression introduced by a previous security
update that caused problems booting on certain s390 systems.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6.18.dfsg.1-26etch2.

We recommend that you upgrade your linux-2.6, fai-kernels, and";
tag_summary = "The remote host is missing an update to linux-2.6
announced via advisory DSA 2003-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202003-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.315124");
 script_version("$Revision: 8250 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-02-25 22:02:04 +0100 (Thu, 25 Feb 2010)");
 script_cve_id("CVE-2009-3080", "CVE-2009-3726", "CVE-2009-4005", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4536", "CVE-2010-0007", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 2003-1 (linux-2.6)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.18", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tree-2.6.18", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.18-6", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.18", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.18", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.18", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-alpha", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-alpha-legacy", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-alpha-legacy", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-alpha-generic", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-alpha", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-alpha-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-alpha-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-alpha", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-alpha-generic", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-vserver", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-vserver-amd64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-arm", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s3c2410", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-ixp4xx", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-ixp4xx", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-footbridge", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-footbridge", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-s3c2410", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-iop32x", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-rpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-rpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-iop32x", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc64-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-parisc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-parisc64-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-hppa", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-k7", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-k7", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-486", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-i386", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-686-bigmem", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-486", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-k7", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-686-bigmem", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-k7", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-xen-vserver-686", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-itanium", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-ia64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-mckinley", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-mckinley", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-itanium", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-qemu", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r4k-ip22", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sb1-bcm91250a", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r5k-ip32", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-mips", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sb1-bcm91250a", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r5k-ip32", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-qemu", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r4k-ip22", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r5k-cobalt", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r3k-kn02", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-r4k-kn04", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-mipsel", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r4k-kn04", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r5k-cobalt", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-r3k-kn02", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-powerpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-prep", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-powerpc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc-miboot", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-prep", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc-miboot", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-powerpc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-powerpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-powerpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-powerpc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-powerpc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s390x", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-s390x", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s390-tape", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-s390", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-s390x", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-s390", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-s390", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-s390x", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sparc64-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sparc64-smp", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sparc32", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-all-sparc", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sparc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-sparc32", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-6-vserver-sparc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-vserver-sparc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-6-sparc64", ver:"2.6.18.dfsg.1-26etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
