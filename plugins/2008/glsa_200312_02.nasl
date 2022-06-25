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
tag_insight = "A flaw in the do_brk() function of the Linux kernel 2.4.22 and earlier can
be exploited by local users or malicious services to gain root privileges.";
tag_solution = "It is recommended that all Gentoo Linux users upgrade their machines to use
the latest stable version of their preferred kernel sources.

    # emerge sync
    # emerge -pv [your preferred kernel sources]
    # emerge [your preferred kernel sources]
    # [update the /usr/src/linux symlink]
    # [compile and install your new kernel]
    # [emerge any necessary kernel module ebuilds]
    # [reboot]

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200312-02
http://bugs.gentoo.org/show_bug.cgi?id=34844";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200312-02.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300591");
 script_version("$Revision: 6596 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:21:37 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(9138);
 script_cve_id("CVE-2003-0961");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Gentoo Security Advisory GLSA 200312-02 (Kernel)");



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
if ((res = ispkgvuln(pkg:"aa-sources", unaffected: make_list("ge 2.4.23_pre6-r3"), vulnerable: make_list("lt 2.4.23_pre6-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ck-sources", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gentoo-sources", unaffected: make_list("ge 2.4.20-r9"), vulnerable: make_list("lt 2.4.20-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gentoo-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"grsec-sources", unaffected: make_list("ge 2.4.22.1.9.12-r1"), vulnerable: make_list("lt 2.4.22.1.9.12-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"grsec-sources", unaffected: make_list("ge 2.4.22.2.0_rc3-r1"), vulnerable: make_list("lt 2.4.22.2.0_rc3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gs-sources", unaffected: make_list("ge 2.4.23_pre8-r1"), vulnerable: make_list("lt 2.4.23_pre8-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"hardened-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"hardened-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ia64-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mips-sources", unaffected: make_list("ge 2.4.22-r4"), vulnerable: make_list("lt 2.4.22-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mips-sources", unaffected: make_list("ge 2.4.22-r5"), vulnerable: make_list("lt 2.4.22-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"openmosix-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-benh", unaffected: make_list("ge 2.4.20-r9"), vulnerable: make_list("lt 2.4.20-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-benh", unaffected: make_list("ge 2.4.21-r2"), vulnerable: make_list("lt 2.4.21-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-benh", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-crypto", unaffected: make_list("ge 2.4.20-r1"), vulnerable: make_list("lt 2.4.20-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"selinux-sources", unaffected: make_list("ge 2.4.21-r5"), vulnerable: make_list("lt 2.4.21-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sparc-sources", unaffected: make_list("ge 2.4.23"), vulnerable: make_list("lt 2.4.23"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"usermode-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"wolk-sources", unaffected: make_list("ge 4.10_pre7-r1"), vulnerable: make_list("lt 4.10_pre7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"wolk-sources", unaffected: make_list("ge 4.9-r2"), vulnerable: make_list("lt 4.9-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"xfs-sources", unaffected: make_list("ge 2.4.20-r4"), vulnerable: make_list("lt 2.4.20-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
