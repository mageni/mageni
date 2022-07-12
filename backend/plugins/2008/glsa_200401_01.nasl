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
tag_insight = "A critical security vulnerability has been found in recent Linux kernels
which allows for local privilege escalation.";
tag_solution = "Users are encouraged to upgrade to the latest available sources for their
system:

    $> emerge sync
    $> emerge -pv your-favourite-sources
    $> emerge your-favourite-sources
    $> # Follow usual procedure for compiling and installing a kernel.
    $> # If you use genkernel, run genkernel as you would do normally.

    $> # IF YOUR KERNEL IS MARKED as 'remerge required!' THEN
    $> # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    $> # REPORTS THAT THE SAME VERSION IS INSTALLED.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200401-01
http://bugs.gentoo.org/show_bug.cgi?id=37292
http://isec.pl/vulnerabilities/isec-0012-mremap.txt";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200401-01.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300994");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_name("Gentoo Security Advisory GLSA 200401-01 (Kernel)");



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
if ((res = ispkgvuln(pkg:"sys-kernel/aa-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r2"), vulnerable: make_list("lt 2.4.21-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/arm-sources", unaffected: make_list("ge 2.4.19-r2"), vulnerable: make_list("lt 2.4.19-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r1"), vulnerable: make_list("lt 2.4.9.32.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.1_rc3"), vulnerable: make_list("lt 2.6.1_rc3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gaming-sources", unaffected: make_list("ge 2.4.20-r7"), vulnerable: make_list("lt 2.4.20-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.1_rc3"), vulnerable: make_list("lt 2.6.1_rc3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-sources", unaffected: make_list("gt 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/grsec-sources", unaffected: make_list("gt 2.4.23.2.0_rc4-r1"), vulnerable: make_list("lt 2.4.23.2.0_rc4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gs-sources", unaffected: make_list("ge 2.4.23_pre8-r2"), vulnerable: make_list("lt 2.4.23_pre8-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.22-r2"), vulnerable: make_list("lt 2.4.22-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.23_p4-r2"), vulnerable: make_list("lt 2.4.23_p4-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.22-r2"), vulnerable: make_list("lt 2.4.22-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-prepatch-sources", unaffected: make_list("ge 2.4.24_pre2-r1"), vulnerable: make_list("lt 2.4.24_pre2-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-sources", unaffected: make_list("ge 2.4.23-r2"), vulnerable: make_list("lt 2.4.23-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mm-sources", unaffected: make_list("ge 2.6.1_rc1-r2"), vulnerable: make_list("lt 2.6.1_rc1-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pfeifer-sources", unaffected: make_list("ge 2.4.21.1_pre4-r1"), vulnerable: make_list("lt 2.4.21.1_pre4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r4"), vulnerable: make_list("lt 2.4.21-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-development-sources", unaffected: make_list("ge 2.6.1_rc1-r1"), vulnerable: make_list("lt 2.6.1_rc1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources-benh", unaffected: make_list("ge 2.4.22-r4"), vulnerable: make_list("lt 2.4.22-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources-crypto", unaffected: make_list("ge 2.4.20-r2"), vulnerable: make_list("lt 2.4.20-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.24"), vulnerable: make_list("lt 2.4.24"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-dev-sources", unaffected: make_list("ge 2.6.1_rc2"), vulnerable: make_list("lt 2.6.1_rc2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.24"), vulnerable: make_list("lt 2.4.24"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/usermode-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-prepatch-sources", unaffected: make_list("ge 2.4.25_pre4"), vulnerable: make_list("lt 2.4.25_pre4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.24"), vulnerable: make_list("lt 2.4.24"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/win4lin-sources", unaffected: make_list("ge 2.6.0-r1"), vulnerable: make_list("lt 2.6.0-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/wolk-sources", unaffected: make_list("ge 4.10_pre7-r2"), vulnerable: make_list("lt 4.10_pre7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xfs-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
