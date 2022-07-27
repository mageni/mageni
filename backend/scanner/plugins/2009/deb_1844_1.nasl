# OpenVAS Vulnerability Test
# $Id: deb_1844_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1844-1 (linux-2.6.24)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2009-1385

Neil Horman discovered a missing fix from the e1000 network driver.
A remote user may cause a denial of service by way of a kernel panic
triggered by specially crafted frame sizes.

CVE-2009-1389

Michael Tokarev discovered an issue in the r8169 network driver.
Remote users on the same LAN may cause a denial of service by way
of a kernel panic triggered by receiving a large size frame.

CVE-2009-1630

Frank Filz discovered that local users may be able to execute
files without execute permission when accessed via an nfs4 mount.

CVE-2009-1633

Jeff Layton and Suresh Jayaraman fixed several buffer overflows in
the CIFS filesystem which allow remote servers to cause memory
corruption.

CVE-2009-1895

Julien Tinnes and Tavis Ormandy reported and issue in the Linux
vulnerability code. Local users can take advantage of a setuid
binary that can either be made to dereference a NULL pointer or
drop privileges and return control to the user. This allows a
user to bypass mmap_min_addr restrictions which can be exploited
to execute arbitrary code.

CVE-2009-1914

Mikulas Patocka discovered an issue in sparc64 kernels that allows
local users to cause a denial of service (crash) by reading the
/proc/iomem file.

CVE-2009-1961

Miklos Szeredi reported an issue in the ocfs2 filesystem. Local
users can create a denial of service (filesystem deadlock) using
a particular sequence of splice system calls.

CVE-2009-2406
CVE-2009-2407

Ramon de Carvalho Valle discovered two issues with the eCryptfs
layered filesystem using the fsfuzzer utility. A local user with
permissions to perform an eCryptfs mount may modify the contents
of a eCryptfs file, overflowing the stack and potentially gaining
elevated privileges.

For the stable distribution (etch), these problems have been fixed in
version 2.6.24-6~etchnhalf.8etch2.

We recommend that you upgrade your linux-2.6.24 packages.";
tag_summary = "The remote host is missing an update to linux-2.6.24
announced via advisory DSA 1844-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201844-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306748");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1895", "CVE-2009-1914", "CVE-2009-1961", "CVE-2009-2406", "CVE-2009-2407");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1844-1 (linux-2.6.24)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.24", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.24", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.24", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.24-etchnhalf.1", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.24", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tree-2.6.24", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-legacy", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-common", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-generic", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-alpha", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-alpha-generic", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-alpha-legacy", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-amd64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-amd64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-amd64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-ixp4xx", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-footbridge", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-arm", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-footbridge", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-iop32x", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-ixp4xx", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-iop32x", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-hppa", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-parisc64-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc64-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-parisc", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-686-bigmem", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-486", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-i386", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-686", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-686-bigmem", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-486", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-686", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-mckinley", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-ia64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-mckinley", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-itanium", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-itanium", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-4kc-malta", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sb1a-bcm91480b", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sb1-bcm91250a", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r5k-ip32", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sb1a-bcm91480b", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r4k-ip22", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sb1-bcm91250a", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r4k-ip22", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-4kc-malta", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-mips", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-5kc-malta", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r5k-ip32", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-5kc-malta", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-mipsel", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-r5k-cobalt", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-r5k-cobalt", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc-miboot", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-powerpc64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-powerpc", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-powerpc-miboot", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390-tape", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-s390x", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-s390", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-s390", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390x", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-s390", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sparc64-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sparc64-smp", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-sparc64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.24-etchnhalf.1-all-sparc", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-etchnhalf.1-sparc64", ver:"2.6.24-6~etchnhalf.8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
