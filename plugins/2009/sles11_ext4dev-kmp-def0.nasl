#
#VID 80db93c687bbdeb62c79f877c742f4bb
# OpenVAS Vulnerability Test
# $
# Description: Security update for the Linux kernel
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
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=408304");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=459065");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=460284");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=464360");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=465854");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=467518");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=474062");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=483706");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=484931");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=486430");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=486803");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=487106");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=487755");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=487755");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=487987");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=489005");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=489105");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=490368");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=490608");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=490902");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=491289");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=491430");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=492282");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=492760");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=492768");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=493392");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=493991");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=494463");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=495068");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=495515");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=495668");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=495816");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=496027");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=496353");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=496398");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=496399");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=496502");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=496878");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=497807");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=498042");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=498237");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499558");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499772");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499845");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499845");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=500508");
 script_oid("1.3.6.1.4.1.25623.1.0.308372");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
 script_cve_id("CVE-2009-1439", "CVE-2009-1337", "CVE-2009-1265", "CVE-2009-1242", "CVE-2009-1360", "CVE-2009-1192");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("SLES11: Security update for the Linux kernel");



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
if ((res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.27.23_0.1~7.1.7", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.27.23_0.1~7.1.7", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-vmi", rpm:"ext4dev-kmp-vmi~0_2.6.27.23_0.1~7.1.7", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.27.23_0.1~7.1.7", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.23~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
