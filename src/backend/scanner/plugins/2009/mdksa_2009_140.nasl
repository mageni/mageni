# OpenVAS Vulnerability Test
# $Id: mdksa_2009_140.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:140 (gaim)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Multiple security vulnerabilities has been identified and fixed
in gaim:

Buffer overflow in the XMPP SOCKS5 bytestream server in Pidgin before
2.5.6 allows remote authenticated users to execute arbitrary code via
vectors involving an outbound XMPP file transfer.  NOTE: some of these
details are obtained from third party information (CVE-2009-1373).

Multiple integer overflows in the msn_slplink_process_msg functions
in the MSN protocol handler in (1) libpurple/protocols/msn/slplink.c
and (2) libpurple/protocols/msnp9/slplink.c in Pidgin before 2.5.6
on 32-bit platforms allow remote attackers to execute arbitrary code
via a malformed SLP message with a crafted offset value, leading to
buffer overflows.  NOTE: this issue exists because of an incomplete
fix for CVE-2008-2927 (CVE-2009-1376).

The updated packages have been patched to prevent this.

Affected: Corporate 3.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:140";
tag_summary = "The remote host is missing an update to gaim
announced via advisory MDVSA-2009:140.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304453");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1373", "CVE-2008-2927", "CVE-2009-1376");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:140 (gaim)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms");
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

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gaim", rpm:"gaim~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gaim-devel", rpm:"gaim-devel~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gaim-perl", rpm:"gaim-perl~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gaim-tcl", rpm:"gaim-tcl~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgaim-remote0", rpm:"libgaim-remote0~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgaim-remote0-devel", rpm:"libgaim-remote0-devel~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gaim-remote0", rpm:"lib64gaim-remote0~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gaim-remote0-devel", rpm:"lib64gaim-remote0-devel~1.5.0~0.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
