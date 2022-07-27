# OpenVAS Vulnerability Test
# $Id: deb_1082_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1082-1
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
tag_insight = "For details, please visit the referenced security advisories.

The following matrix explains which kernel version for which architecture
fix the problems mentioned above:

Debian 3.1 (sarge)
Source                          2.4.17-1woody4
HP Precision architecture       32.5
Intel IA-64 architecture        011226.18
IBM S/390 architecture/image    2.4.17-2.woody.5
IBM S/390 architecture/patch    0.0.20020816-0.woody.4
PowerPC architecture (apus)     2.4.17-6
MIPS architecture               2.4.17-0.020226.2.woody7

We recommend that you upgrade your kernel package immediately and reboot";
tag_summary = "The remote host is missing an update to kernel-image-2.4.17-hppa kernel-image-2.4.17-ia64 kernel-image-2.4.17-s390 kernel-patch-2.4.17-apus kernel-patch-2.4.17-mips kernel-patch-2.4.17-s390 kernel-source-2.4.17
announced via advisory DSA 1082-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201082-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300424");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0427", "CVE-2005-0489", "CVE-2004-0394", "CVE-2004-0447", "CVE-2004-0554", "CVE-2004-0565", "CVE-2004-0685", "CVE-2005-0001", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1016", "CVE-2004-1333", "CVE-2004-0997", "CVE-2004-1335", "CVE-2004-1017", "CVE-2005-0124", "CVE-2003-0985", "CVE-2003-0984", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-0138", "CVE-2004-1068", "CVE-2004-1234", "CVE-2005-0003", "CVE-2004-1235", "CVE-2005-0504", "CVE-2005-0384", "CVE-2005-0135");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1082-1 (kernel-2.4.17)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.17-hppa", ver:"32.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.17-ia64", ver:"011226.18", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.17-mips", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.17-s390", ver:"0.0.20020816-0.woody.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-doc-2.4.17", ver:"2.4.17-1woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-source-2.4.17", ver:"2.4.17-1woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.17-hppa", ver:"32.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-32", ver:"32.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-32-smp", ver:"32.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-64", ver:"32.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-64-smp", ver:"32.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mkcramfs", ver:"2.4.17-1woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.17-ia64", ver:"011226.18", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-itanium", ver:"011226.18", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-itanium-smp", ver:"011226.18", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-mckinley", ver:"011226.18", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-mckinley-smp", ver:"011226.18", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.17", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-s390", ver:"2.4.17-2.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-headers-2.4.17-apus", ver:"2.4.17-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-apus", ver:"2.4.17-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-apus", ver:"2.4.17-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-patch-2.4.17-apus", ver:"2.4.17-6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-r4k-ip22", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-r5k-ip22", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-r3k-kn02", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-2.4.17-r4k-kn04", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.17-0.020226.2.woody7", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
