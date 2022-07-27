# OpenVAS Vulnerability Test
# $Id: mdksa_2009_098_1.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:098-1 (krb5)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in krb5:

The get_input_token function in the SPNEGO implementation in MIT
Kerberos 5 (aka krb5) 1.5 through 1.6.3 allows remote attackers to
cause a denial of service (daemon crash) and possibly obtain sensitive
information via a crafted length value that triggers a buffer over-read
(CVE-2009-0844).

The spnego_gss_accept_sec_context function in
lib/gssapi/spnego/spnego_mech.c in MIT Kerberos 5 (aka krb5) 1.5
through 1.6.3, when SPNEGO is used, allows remote attackers to cause
a denial of service (NULL pointer dereference and daemon crash) via
invalid ContextFlags data in the reqFlags field in a negTokenInit token
(CVE-2009-0845).

The asn1_decode_generaltime function in lib/krb5/asn.1/asn1_decode.c in
the ASN.1 GeneralizedTime decoder in MIT Kerberos 5 (aka krb5) before
1.6.4 allows remote attackers to cause a denial of service (daemon
crash) or possibly execute arbitrary code via vectors involving an
invalid DER encoding that triggers a free of an uninitialized pointer
(CVE-2009-0846).

The asn1buf_imbed function in the ASN.1 decoder in MIT Kerberos 5
(aka krb5) 1.6.3, when PK-INIT is used, allows remote attackers to
cause a denial of service (application crash) via a crafted length
value that triggers an erroneous malloc call, related to incorrect
calculations with pointer arithmetic (CVE-2009-0847).

The updated packages have been patched to correct these issues.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:098-1";
tag_summary = "The remote host is missing an update to krb5
announced via advisory MDVSA-2009:098-1.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311802");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:098-1 (krb5)");



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
if ((res = isrpmvuln(pkg:"ftp-client-krb5", rpm:"ftp-client-krb5~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ftp-server-krb5", rpm:"ftp-server-krb5~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-client-krb5", rpm:"telnet-client-krb5~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"telnet-server-krb5", rpm:"telnet-server-krb5~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.6.2~7.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
