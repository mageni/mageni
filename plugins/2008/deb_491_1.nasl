# OpenVAS Vulnerability Test
# $Id: deb_491_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 491-1
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
tag_insight = "Several serious problems have been discovered in the Linux kernel.
This update takes care of Linux 2.4.17 for the MIPS architecture.  The
Common Vulnerabilities and Exposures project identifies the following
problems that will be fixed with this update:

CVE-2004-0003

A vulnerability has been discovered in the R128 drive in the Linux
kernel which could potentially lead an attacker to gain
unauthorised privileges.  Alan Cox and Thomas Biege developed a
correction for this

CVE-2004-0010

Arjan van de Ven discovered a stack-based buffer overflow in the
ncp_lookup function for ncpfs in the Linux kernel, which could
lead an attacker to gain unauthorised privileges.  Petr Vandrovec
developed a correction for this.

CVE-2004-0109

zen-parse discovered a buffer overflow vulnerability in the
ISO9660 filesystem component of Linux kernel which could be abused
by an attacker to gain unauthorised root access.  Sebastian
Krahmer and Ernie Petrides developed a correction for this.

CVE-2004-0177

Solar Designer discovered an information leak in the ext3 code of
Linux.  In a worst case an attacker could read sensitive data such
as cryptographic keys which would otherwise never hit disk media.
Theodore Ts'o developed a correction for this.

CVE-2004-0178

Andreas Kies discovered a denial of service condition in the Sound
Blaster driver in Linux.  He also developed a correction for this.

These problems are also fixed by upstream in Linux 2.4.26 and future
versions of 2.6.

The following security matrix explains which kernel versions for which
architectures are already fixed and which will be removed instead.

Architecture   stable (woody)            unstable (sid)     remove in sid
source         2.4.19-4.woody2           2.4.25-3           2.4.19-11
mips           2.4.19-0.020911.1.woody4  2.4.25-0.040415.1  2.4.19-0.020911.8
h
We recommend that you upgrade your kernel packages immediately, either";
tag_summary = "The remote host is missing an update to kernel-source-2.4.19 kernel-patch-2.4.19-mips
announced via advisory DSA 491-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20491-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302175");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 491-1 (kernel-source-2.4.19 kernel-patch-2.4.19-mips)");



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
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.19", ver:"2.4.19-4.woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.19", ver:"2.4.19-4.woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.19-mips", ver:"2.4.19-0.020911.1.woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.19", ver:"2.4.19-0.020911.1.woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.19-r4k-ip22", ver:"2.4.19-0.020911.1.woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.19-r5k-ip22", ver:"2.4.19-0.020911.1.woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.19-0.020911.1.woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
