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
tag_insight = "Multiple permission vulnerabilities have been found in the Linux kernel,
allowing an attacker to change the group IDs of files mounted on a remote
filesystem (CVE-2004-0497), as well as an issue in 2.6 series kernels
which allows /proc permissions to be bypassed. A context sharing
vulnerability in vserver-sources is also handled by this advisory as well
as CVE-2004-0447, CVE-2004-0496 and CVE-2004-0565. Patched, or updated
versions of these kernels have been released and details are included
along with this advisory.";
tag_solution = "Users are encouraged to upgrade to the latest available sources for their
system:

    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources

    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-16
http://bugs.gentoo.org/show_bug.cgi?id=56171
http://bugs.gentoo.org/show_bug.cgi?id=56479
http://www.securityfocus.com/archive/1/367977";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200407-16.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302747");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2004-0447", "CVE-2004-0496", "CVE-2004-0497", "CVE-2004-0565");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200407-16 (Kernel)");



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
if ((res = ispkgvuln(pkg:"sys-kernel/aa-sources", unaffected: make_list("rge 2.4.23-r2", "ge 2.6.5-r5"), vulnerable: make_list("lt 2.6.5-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r9"), vulnerable: make_list("lt 2.4.21-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("rge 2.4.26-r1", "ge 2.6.7-r5"), vulnerable: make_list("lt 2.6.7-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r8"), vulnerable: make_list("lt 2.4.9.32.7-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.8_rc1"), vulnerable: make_list("lt 2.6.8_rc1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7-r8"), vulnerable: make_list("lt 2.6.7-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-sources", unaffected: make_list("rge 2.4.19-r18", "rge 2.4.20-r21", "rge 2.4.22-r13", "rge 2.4.25-r6", "ge 2.4.26-r5"), vulnerable: make_list("lt 2.4.26-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.26.2.0-r6"), vulnerable: make_list("lt 2.4.26.2.0-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r8"), vulnerable: make_list("lt 2.4.25_pre7-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7_p1-r2"), vulnerable: make_list("lt 2.6.7_p1-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.26_p6-r1"), vulnerable: make_list("lt 2.4.26_p6-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r7"), vulnerable: make_list("lt 2.4.24-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mm-sources", unaffected: make_list("ge 2.6.7-r6"), vulnerable: make_list("lt 2.6.7-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r11"), vulnerable: make_list("lt 2.4.22-r11"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r9"), vulnerable: make_list("lt 2.4.23-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r11"), vulnerable: make_list("lt 2.4.21-r11"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pegasos-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.26-r2"), vulnerable: make_list("lt 2.4.26-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.26-r3"), vulnerable: make_list("lt 2.4.26-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/uclinux-sources", unaffected: make_list("rge 2.4.26_p0-r3", "ge 2.6.7_p0-r2"), vulnerable: make_list("lt 2.6.7_p0-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r6", "rge 2.4.26-r3", "ge 2.6.6-r4"), vulnerable: make_list("lt 2.6.6-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vserver-sources", unaffected: make_list("ge 2.4.26.1.28-r1"), vulnerable: make_list("lt 2.4.26.1.28-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/win4lin-sources", unaffected: make_list("rge 2.4.26-r3", "ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/wolk-sources", unaffected: make_list("rge 4.9-r10", "rge 4.11-r7", "ge 4.14-r4"), vulnerable: make_list("lt 4.14-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xbox-sources", unaffected: make_list("rge 2.4.26-r3", "ge 2.6.7-r2"), vulnerable: make_list("lt 2.6.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-sources", unaffected: make_list("ge 2.4.27"), vulnerable: make_list("lt 2.4.27"))) != NULL) {
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
