# OpenVAS Vulnerability Test
# $Id: deb_047_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 047-1
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
tag_insight = "The kernels used in Debian GNU/Linux 2.2 have been found to have
multiple security problems. This is a list of problems based
on the 2.2.19 release notes as found on http://www.linux.org.uk/ :

* binfmt_misc used user pages directly
* the CPIA driver had an off-by-one error in the buffer code which made
it possible for users to write into kernel memory
* the CPUID and MSR drivers had a problem in the module unloading code
which could case a system crash if they were set to automatically load
and unload (please note that Debian does not automatically unload kernel
modules)
* There was a possible hang in the classifier code
* The getsockopt and setsockopt system calls did not handle sign bits
correctly which made a local DoS and other attacks possible
* The sysctl system call did not handle sign bits correctly which allowed
a user to write in kernel memory
* ptrace/exec races that could give a local user extra privileges
* possible abuse of a boundary case in the sockfilter code
* SYSV shared memory code could overwrite recently freed memory which might
cause problems
* The packet length checks in the masquerading code were a bit lax
(probably not exploitable)
* Some x86 assembly bugs caused the wrong number of bytes to be copied.
* A local user could deadlock the kernel due to bugs in the UDP port
allocation.

All these problems are fixed in the 2.2.19 kernel, and it is highly
recommend that you upgrade machines to this kernel.

Please note that kernel upgrades are not done automatically. You will
have to explicitly tell the packaging system to install the right kernel
for your system.";
tag_summary = "The remote host is missing an update to various kernel packages
announced via advisory DSA 047-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20047-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301552");
 script_cve_id("CVE-2001-1390","CVE-2001-1391","CVE-2001-1392","CVE-2001-1393","CVE-2001-1394","CVE-2001-1395","CVE-2001-1396","CVE-2001-1397","CVE-2001-1398","CVE-2001-1399","CVE-2001-1400");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 047-1 (various kernel packages)");



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
if ((res = isdpkgvuln(pkg:"kernel-doc-2.2.19", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.2.19", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.19-sparc", ver:"6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.2.19-arm", ver:"20010414", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.2.19-m68k", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.2.19-powerpc", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-riscpc", ver:"20010414", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.19", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-generic", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-jensen", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-nautilus", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-smp", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-amiga", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-atari", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-bvme6000", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-mac", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-mvme147", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-mvme16x", ver:"2.2.19-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.19-compact", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.19-ide", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.2.19-idepci", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-compact", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-ide", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-idepci", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-chrp", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-pmac", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-prep", ver:"2.2.19-2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-sun4cdm", ver:"6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-sun4dm-pci", ver:"6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-sun4dm-smp", ver:"6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-sun4u-smp", ver:"6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.2.19-sun4u", ver:"6", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
