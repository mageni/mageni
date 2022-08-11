#
#VID ab571c76de3bf9c7bafb83437a2d83aa
# OpenVAS Vulnerability Test
# $
# Description: Security update for Linux kernel
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    ext4dev-kmp-default
    ext4dev-kmp-pae
    ext4dev-kmp-vmi
    ext4dev-kmp-xen
    kernel-default
    kernel-default-base
    kernel-pae
    kernel-pae-base
    kernel-source
    kernel-syms
    kernel-vmi
    kernel-vmi-base
    kernel-xen
    kernel-xen-base


More details may also be found by searching for the SuSE
Enterprise Server 11 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

if(description)
{
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=417417");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=439348");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=441420");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=450468");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=457472");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=458222");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=462913");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=463829");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=465854");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=465955");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=467174");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=467317");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=467381");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=469576");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=470238");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=471249");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=472783");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=473881");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=474335");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=476330");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=477624");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=478534");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=479558");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=479617");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=479730");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=479784");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480391");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480448");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480524");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480617");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480749");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480753");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=480809");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=481749");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=482052");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=482220");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=482506");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=482614");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=482796");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=482818");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=483706");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=484529");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=484664");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=484767");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=485089");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=486001");
 script_oid("1.3.6.1.4.1.25623.1.0.304721");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
 script_cve_id("CVE-2009-1072", "CVE-2009-0676", "CVE-2009-0835");
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
 script_name("SLES11: Security update for Linux kernel");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.27.21_0.1~7.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.27.21_0.1~7.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-vmi", rpm:"ext4dev-kmp-vmi~0_2.6.27.21_0.1~7.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.27.21_0.1~7.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.21~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.21~0.1.2", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
