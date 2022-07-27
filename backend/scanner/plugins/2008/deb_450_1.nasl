# OpenVAS Vulnerability Test
# $Id: deb_450_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 450-1
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
tag_insight = "Several local root exploits have been discovered recently in the Linux
kernel.  This security advisory updates the mips kernel 2.4.19 for
Debian GNU/Linux.  The Common Vulnerabilities and Exposures project
identifies the following problems that are fixed with this update:

CVE-2003-0961:

An integer overflow in brk() system call (do_brk() function) for
Linux allows a local attacker to gain root privileges.  Fixed
upstream in Linux 2.4.23.

CVE-2003-0985:

Paul Starzetz discovered a flaw in bounds checking in mremap() in
the Linux kernel (present in version 2.4.x and 2.6.x) which may
allow a local attacker to gain root privileges.  Version 2.2 is not
affected by this bug.  Fixed upstream in Linux 2.4.24.

CVE-2004-0077:

Paul Starzetz and Wojciech Purczynski of isec.pl discovered a
critical security vulnerability in the memory management code of
Linux inside the mremap(2) system call.  Due to missing function
return value check of internal functions a local attacker can gain
root privileges.  Fixed upstream in Linux 2.4.25 and 2.6.3.

For the stable distribution (woody) these problems have been fixed in
version 2.4.19-0.020911.1.woody3 of mips images and version
2.4.19-4.woody1 of kernel source.

For the unstable distribution (sid) this problem will be fixed soon
with the next upload of a 2.4.19 kernel image and in version
2.4.22-0.030928.3 for 2.4.22.

We recommend that you upgrade your Linux kernel packages immediately.";
tag_summary = "The remote host is missing an update to kernel-source-2.4.19, kernel-patch-2.4.19-mips
announced via advisory DSA 450-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20450-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300034");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0961", "CVE-2003-0985", "CVE-2004-0077");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 450-1 (kernel-source-2.4.19, kernel-patch-2.4.19-mips)");



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
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.19", ver:"2.4.19-4.woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.19", ver:"2.4.19-4.woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.19-mips", ver:"2.4.19-0.020911.1.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.19", ver:"2.4.19-0.020911.1.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.19-r4k-ip22", ver:"2.4.19-0.020911.1.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.19-r5k-ip22", ver:"2.4.19-0.020911.1.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.19-0.020911.1.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
