# OpenVAS Vulnerability Test
# $Id: deb_1428_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1481-1
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
tag_insight = "Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-3104

Eric Sandeen provided a backport of Tejun Heo's fix for a local denial
of service vulnerability in sysfs. Under memory pressure, a dentry
structure maybe reclaimed resulting in a bad pointer dereference causing
an oops during a readdir.

CVE-2007-4997

Chris Evans discovered an issue with certain drivers that make use of the
Linux kernel's ieee80211 layer. A remote user could generate a malicious
802.11 frame that could result in a denial of service (crash). The ipw2100
driver is known to be affected by this issue, while the ipw2200 is
believed not to be.

CVE-2007-5500

Scott James Remnant diagnosed a coding error in the implementation of
ptrace which could be used by a local user to cause the kernel to enter
an infinite loop.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-13etch5.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 4.0 (etch)
fai-kernels                 1.17+etch.13etch5
user-mode-linux             2.6.18-1um-2etch.13etch5

We recommend that you upgrade your kernel package immediately and reboot";
tag_summary = "The remote host is missing an update to linux-2.6
announced via advisory DSA 1428-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201428-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300492");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2007-3104", "CVE-2007-4997", "CVE-2007-5500");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1428-1 (linux-2.6)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.18", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.18", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.18", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.18", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.18-5", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tree-2.6.18", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-alpha", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-generic", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-legacy", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-alpha-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-alpha", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-generic", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-legacy", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-alpha-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-alpha", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-vserver-amd64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fai-kernels", ver:"1.17+etch.13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-arm", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-footbridge", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-iop32x", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-ixp4xx", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-rpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s3c2410", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-footbridge", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-iop32x", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-ixp4xx", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-rpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s3c2410", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-hppa", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-parisc64-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-parisc64-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-486", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-686-bigmem", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-i386", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-k7", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-k7", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-486", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-686-bigmem", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-k7", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-k7", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.18-5-xen-vserver-686", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"user-mode-linux", ver:"2.6.18-1um-2etch.13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-ia64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-itanium", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-mckinley", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-itanium", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-mckinley", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-mips", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-qemu", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r4k-ip22", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r5k-ip32", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sb1-bcm91250a", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-qemu", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r4k-ip22", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r5k-ip32", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sb1-bcm91250a", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sb1a-bcm91480b", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-mipsel", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r3k-kn02", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r4k-kn04", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-r5k-cobalt", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r3k-kn02", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r4k-kn04", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-r5k-cobalt", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-powerpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc-miboot", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-powerpc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-prep", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-powerpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-powerpc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc-miboot", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-powerpc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-prep", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-powerpc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-powerpc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-s390", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s390", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-s390x", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-s390x", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390-tape", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-s390x", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-s390x", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-all-sparc", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc32", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-sparc64-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.18-5-vserver-sparc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc32", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-sparc64-smp", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.18-5-vserver-sparc64", ver:"2.6.18.dfsg.1-13etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
