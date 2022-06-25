# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1428.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1428 ()
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
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:1428.

The XML Security Library is a C library based on libxml2 and OpenSSL. It
implements the XML Signature Syntax and Processing and XML Encryption
Syntax and Processing standards. HMAC is used for message authentication
using cryptographic hash functions. The HMAC algorithm allows the hash
output to be truncated (as documented in RFC 2104).

A missing check for the recommended minimum length of the truncated form of
HMAC-based XML signatures was found in xmlsec1. An attacker could use this
flaw to create a specially-crafted XML file that forges an XML signature,
allowing the attacker to bypass authentication that is based on the XML
Signature specification. (CVE-2009-0217)

Users of xmlsec1 should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing the updated
packages, applications that use the XML Security Library must be restarted
for the update to take effect.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311590");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2009-0217");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("RedHat Security Advisory RHSA-2009:1428");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1428.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 script_xref(name : "URL" , value : "http://www.w3.org/TR/xmldsig-core/");
 script_xref(name : "URL" , value : "http://tools.ietf.org/html/rfc2104");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.6~3.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-debuginfo", rpm:"xmlsec1-debuginfo~1.2.6~3.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-devel", rpm:"xmlsec1-devel~1.2.6~3.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-openssl", rpm:"xmlsec1-openssl~1.2.6~3.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-openssl-devel", rpm:"xmlsec1-openssl-devel~1.2.6~3.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-debuginfo", rpm:"xmlsec1-debuginfo~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-gnutls", rpm:"xmlsec1-gnutls~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-nss", rpm:"xmlsec1-nss~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-openssl", rpm:"xmlsec1-openssl~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-devel", rpm:"xmlsec1-devel~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-gnutls-devel", rpm:"xmlsec1-gnutls-devel~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-nss-devel", rpm:"xmlsec1-nss-devel~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1-openssl-devel", rpm:"xmlsec1-openssl-devel~1.2.9~8.1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
