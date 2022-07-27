# OpenVAS Vulnerability Test
# $Id: mdksa_2009_318.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:318 (xmlsec1)
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
in xmlsec1:

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xmlsec1 prior to
1.2.12. An attacker could use this flaw to create a specially-crafted
XML file that forges an XML signature, allowing the attacker to
bypass authentication that is based on the XML Signature specification
(CVE-2009-0217).

All versions of libtool prior to 2.2.6b suffers from a local
privilege escalation vulnerability that could be exploited under
certain conditions to load arbitrary code (CVE-2009-3736).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update fixes this vulnerability.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:318
http://www.kb.cert.org/vuls/id/466161";
tag_summary = "The remote host is missing an update to xmlsec1
announced via advisory MDVSA-2009:318.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305826");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-0217", "CVE-2009-3736");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:318 (xmlsec1)");



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
if ((res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-devel", rpm:"libxmlsec1-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls-devel", rpm:"libxmlsec1-gnutls-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss-devel", rpm:"libxmlsec1-nss-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl-devel", rpm:"libxmlsec1-openssl-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-1", rpm:"lib64xmlsec1-1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-devel", rpm:"lib64xmlsec1-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls1", rpm:"lib64xmlsec1-gnutls1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls-devel", rpm:"lib64xmlsec1-gnutls-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss1", rpm:"lib64xmlsec1-nss1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss-devel", rpm:"lib64xmlsec1-nss-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl1", rpm:"lib64xmlsec1-openssl1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl-devel", rpm:"lib64xmlsec1-openssl-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
