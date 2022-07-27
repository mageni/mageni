# OpenVAS Vulnerability Test
# $Id: mdksa_2009_037.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:037 (bind)
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
tag_insight = "Internet Systems Consortium (ISC) BIND 9.6.0 and earlier does not
properly check the return value from the OpenSSL EVP_VerifyFinal
function, which allows remote attackers to bypass validation of
the certificate chain via a malformed SSL/TLS signature, a similar
vulnerability to CVE-2008-5077 and CVE-2009-0025.

In this particular case the DSA_verify function was fixed with
MDVSA-2009:002, this update does however address the RSA_verify
function (CVE-2009-0265).

Affected: 2008.0, 2008.1, 2009.0, Corporate 3.0, Corporate 4.0,
          Multi Network Firewall 2.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:037";
tag_summary = "The remote host is missing an update to bind
announced via advisory MDVSA-2009:037.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307286");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
 script_cve_id("CVE-2008-5077", "CVE-2009-0025", "CVE-2009-0265");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:037 (bind)");



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
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.4.2~1.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.4.2~1.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.4.2~1.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.5.0~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.5.0~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.5.0~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.5.0~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.5.0~6.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.5.0~6.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.5.0~6.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.5.0~6.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.3~6.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.3~6.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.3~6.7.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.5~0.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.5~0.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.5~0.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.3~6.7.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.3~6.7.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.3~6.7.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
