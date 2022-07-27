#
#VID 180ffe58c62210bba55d0af594f5207f
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
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=410452");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=441650");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=448410");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=459146");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=466554");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=471396");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=472342");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=476582");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=477816");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=483375");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=483706");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=487412");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=490030");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=492547");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=498708");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=501563");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=504646");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=509753");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=511306");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=514022");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=515640");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=524242");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=527754");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=528769");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=531260");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=531384");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=531437");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=531533");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=531633");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=532063");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=532443");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=532598");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=533267");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=533267");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=534065");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=534202");
 script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=534214");
 script_oid("1.3.6.1.4.1.25623.1.0.306383");
 script_version("$Revision: 6666 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 15:13:36 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-2909", "CVE-2009-3002", "CVE-2009-2910");
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.27.37_0.1~7.1.18", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.27.37_0.1~7.1.18", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-vmi", rpm:"ext4dev-kmp-vmi~0_2.6.27.37_0.1~7.1.18", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.27.37_0.1~7.1.18", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.37~0.1.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
