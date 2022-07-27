# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1335.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1335 ()
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
tag_solution = "OpenSSL users should upgrade to these updated packages, which resolve these
issues and add these enhancements.

Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";

tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:1335.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols, as well as a full-strength
general purpose cryptography library. Datagram TLS (DTLS) is a protocol
based on TLS that is capable of securing datagram transport (for example,
UDP).

Multiple denial of service flaws were discovered in OpenSSL's DTLS
implementation. A remote attacker could use these flaws to cause a DTLS
server to use excessive amounts of memory, or crash on an invalid memory
access or NULL pointer dereference. (CVE-2009-1377, CVE-2009-1378,
CVE-2009-1379, CVE-2009-1386, CVE-2009-1387)

Note: These flaws only affect applications that use DTLS. Red Hat does not
ship any DTLS client or server applications in Red Hat Enterprise Linux.

An input validation flaw was found in the handling of the BMPString and
UniversalString ASN1 string types in OpenSSL's ASN1_STRING_print_ex()
function. An attacker could use this flaw to create a specially-crafted
X.509 certificate that could cause applications using the affected function
to crash when printing certificate contents. (CVE-2009-0590)

Note: The affected function is rarely used. No application shipped with Red
Hat Enterprise Linux calls this function, for example.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308885");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2009-0590", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("RedHat Security Advisory RHSA-2009:1335");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1335.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~12.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8e~12.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~12.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~12.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
