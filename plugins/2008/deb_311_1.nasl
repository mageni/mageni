# OpenVAS Vulnerability Test
# $Id: deb_311_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 311-1
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
tag_insight = "A number of vulnerabilities have been discovered in the Linux kernel.

For a more detailed description of the problems addressed,
please visit the referenced security advisory.

This advisory covers only the i386 (Intel IA32) architectures.  Other
architectures will be covered by separate advisories.

For the stable distribution (woody) on the i386 architecture, these
problems have been fixed in kernel-source-2.4.18 version 2.4.18-9,
kernel-image-2.4.18-1-i386 version 2.4.18-8, and
kernel-image-2.4.18-i386bf version 2.4.18-5woody1.

For the unstable distribution (sid) these problems are fixed in the
2.4.20 series kernels based on Debian sources.

We recommend that you update your kernel packages.

If you are using the kernel installed by the installation system when
the 'bf24' option is selected (for a 2.4.x kernel), you should install
the kernel-image-2.4.18-bf2.4 package.  If you installed a different
kernel-image package after installation, you should install the
corresponding 2.4.18-1 kernel.  You may use the table below as a
guide.

* If 'uname -r' shows: * Install this package:
- ------------------------------------------------------
* 2.4.18-bf2.4         * kernel-image-2.4.18-bf2.4
* 2.4.18-386           * kernel-image-2.4.18-1-386
* 2.4.18-586tsc        * kernel-image-2.4.18-1-586tsc
* 2.4.18-686           * kernel-image-2.4.18-1-686
* 2.4.18-686-smp       * kernel-image-2.4.18-1-686-smp
* 2.4.18-k6            * kernel-image-2.4.18-1-k6
* 2.4.18-k7            * kernel-image-2.4.18-1-k7

NOTE: that this kernel is not binary compatible with the previous
version.  For this reason, the kernel has a different version number
and will not be installed automatically as part of the normal upgrade
process.  Any custom modules will need to be rebuilt in order to work
with the new kernel.  New PCMCIA modules are provided for all of the
above kernels.

NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel.  Remember to read carefully
and follow the instructions given during the kernel upgrade process.";
tag_summary = "The remote host is missing an update to kernel
announced via advisory DSA 311-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20311-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304054");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 311-1 (kernel)");



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
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-386", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-586tsc", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-686", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-686-smp", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-k6", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-1-k7", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-386", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-586tsc", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-686", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-686-smp", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-k6", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-1-k7", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-386", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-586tsc", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-686", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-686-smp", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-k6", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-pcmcia-modules-2.4.18-1-k7", ver:"2.4.18-8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.18-bf2.4", ver:"2.4.18-5woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.18-bf2.4", ver:"2.4.18-5woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.18", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.18", ver:"2.4.18-9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-2.4.18-bf2.4", ver:"3.1.33-6woody1k5woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
