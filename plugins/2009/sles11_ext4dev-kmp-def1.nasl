#
#VID efe472a6c3ff8e53697cca9b64ed6db5
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
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499152");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=495091");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=439775");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=493214");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=516213");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=476525");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=516827");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=509544");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=514644");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=503855");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=509071");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=475149");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=495065");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=498369");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=450658");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=503635");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=497648");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=511243");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=509822");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=507557");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=506361");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=481074");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=484716");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=500429");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=487247");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=478462");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=501396");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=476822");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=485768");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=502903");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=497341");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=498358");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499845");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=491802");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=505578");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=191648");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=185164");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=501651");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=502675");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=502903");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=499278");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=503353");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=395775");
 script_oid("1.3.6.1.4.1.25623.1.0.310454");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
 script_cve_id("CVE-2009-1961", "CVE-2009-1389", "CVE-2009-1385", "CVE-2009-1630");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.27.25_0.1~7.1.12", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.27.25_0.1~7.1.12", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-vmi", rpm:"ext4dev-kmp-vmi~0_2.6.27.25_0.1~7.1.12", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.27.25_0.1~7.1.12", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.25~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
