# OpenVAS Vulnerability Test
# $Id: mdksa_2009_308.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:308 (gnutls)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in gnutls:

gnutls-cli in GnuTLS before 2.6.6 does not verify the activation
and expiration times of X.509 certificates, which allows remote
attackers to successfully present a certificate that is (1) not yet
valid or (2) no longer valid, related to lack of time checks in the
_gnutls_x509_verify_certificate function in lib/x509/verify.c in
libgnutls_x509, as used by (a) Exim, (b) OpenLDAP, and (c) libsoup
(CVE-2009-1417).

A vulnerability have been discovered and corrected in GnuTLS
before 2.8.2, which could allow man-in-the-middle attackers to spoof
arbitrary SSL servers via a crafted certificate issued by a legitimate
Certification Authority (CVE-2009-2730).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update fixes this vulnerability.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:308";
tag_summary = "The remote host is missing an update to gnutls
announced via advisory MDVSA-2009:308.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310278");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-1417", "CVE-2009-2730");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandriva Security Advisory MDVSA-2009:308 (gnutls)");



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
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.0.0~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls13", rpm:"libgnutls13~2.0.0~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~2.0.0~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls13", rpm:"lib64gnutls13~2.0.0~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~2.0.0~2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
