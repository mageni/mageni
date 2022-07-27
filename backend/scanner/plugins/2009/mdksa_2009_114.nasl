# OpenVAS Vulnerability Test
# $Id: mdksa_2009_114.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:114 (ipsec-tools)
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
tag_insight = "Multiple memory leaks in Ipsec-tools before 0.7.2 allow remote
attackers to cause a denial of service (memory consumption) via vectors
involving (1) signature verification during user authentication with
X.509 certificates, related to the eay_check_x509sign function in
src/racoon/crypto_openssl.c; and (2) the NAT-Traversal (aka NAT-T)
keepalive implementation, related to src/racoon/nattraversal.c
(CVE-2009-1632).

The updated packages have been patched to prevent this.

Affected: Corporate 4.0, Multi Network Firewall 2.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:114";
tag_summary = "The remote host is missing an update to ipsec-tools
announced via advisory MDVSA-2009:114.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305049");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
 script_cve_id("CVE-2009-1632");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:114 (ipsec-tools)");



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
if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.6.5~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libipsec0", rpm:"libipsec0~0.6.5~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libipsec0-devel", rpm:"libipsec0-devel~0.6.5~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ipsec0", rpm:"lib64ipsec0~0.6.5~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ipsec0-devel", rpm:"lib64ipsec0-devel~0.6.5~2.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.2.5~0.7.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libipsec-tools0", rpm:"libipsec-tools0~0.2.5~0.7.M20mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
