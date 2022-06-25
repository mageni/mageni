# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "Multiple vulnerabilities have been found in the Linux kernel used by
GNU/Linux systems. Patched, or updated versions of these kernels have been
released and details are included in this advisory.";
tag_solution = "Users are encouraged to upgrade to the latest available sources for their
system:

    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources

    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-02
http://bugs.gentoo.org/show_bug.cgi?id=47881
http://bugs.gentoo.org/show_bug.cgi?id=49637
http://bugs.gentoo.org/show_bug.cgi?id=53804
http://bugs.gentoo.org/show_bug.cgi?id=54976
http://bugs.gentoo.org/show_bug.cgi?id=55698";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200407-02.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302089");
 script_cve_id("CVE-2004-0109","CVE-2004-0133","CVE-2004-0177","CVE-2004-0178","CVE-2004-0181","CVE-2004-0228","CVE-2004-0229","CVE-2004-0394","CVE-2004-0427","CVE-2004-0495","CVE-2004-0535","CVE-2004-0554","CVE-2004-1983");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_name("Gentoo Security Advisory GLSA 200407-02 (Kernel)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-kernel/aa-sources", unaffected: make_list("eq 2.4.23-r2"), vulnerable: make_list("lt 2.4.23-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r8"), vulnerable: make_list("lt 2.4.21-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("eq 2.4.26-r1", "ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r7"), vulnerable: make_list("lt 2.4.9.32.7-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gaming-sources", unaffected: make_list("ge 2.4.20-r14"), vulnerable: make_list("lt 2.4.20-r14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-sources", unaffected: make_list("rge 2.4.19-r17", "rge 2.4.20-r20", "rge 2.4.22-r12", "rge 2.4.25-r5", "ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.26.2.0-r5"), vulnerable: make_list("lt 2.4.26.2.0-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r7"), vulnerable: make_list("lt 2.4.25_pre7-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.26_p6"), vulnerable: make_list("lt 2.4.26_p6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r5"), vulnerable: make_list("lt 2.4.24-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mm-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r10"), vulnerable: make_list("lt 2.4.22-r10"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r8"), vulnerable: make_list("lt 2.4.23-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pegasos-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r10"), vulnerable: make_list("lt 2.4.21-r10"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc64-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/uclinux-sources", unaffected: make_list("ge 2.4.26_p0-r2"), vulnerable: make_list("lt 2.4.26_p0-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r5", "ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vserver-sources", unaffected: make_list("ge 2.4.26.1.3.9-r2"), vulnerable: make_list("lt 2.4.26.1.3.9-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/win4lin-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/wolk-sources", unaffected: make_list("rge 4.9-r9", "rge 4.11-r6", "ge 4.14-r3"), vulnerable: make_list("lt 4.14-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xbox-sources", unaffected: make_list("ge 2.6.7"), vulnerable: make_list("lt 2.6.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xfs-sources", unaffected: make_list("ge 2.4.24-r8"), vulnerable: make_list("lt 2.4.24-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.27"), vulnerable: make_list("le 2.4.26"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
