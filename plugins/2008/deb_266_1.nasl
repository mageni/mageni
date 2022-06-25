# OpenVAS Vulnerability Test
# $Id: deb_266_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 266-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_insight = "Several vulnerabilities have been discovered in krb5, an
implementation of MIT Kerberos.

. A cryptographic weakness in version 4 of the Kerberos protocol
allows an attacker to use a chosen-plaintext attack to impersonate
any principal in a realm.  Additional cryptographic weaknesses in
the krb4 implementation included in the MIT krb5 distribution
permit the use of cut-and-paste attacks to fabricate krb4 tickets
for unauthorized client principals if triple-DES keys are used to
key krb4 services.  These attacks can subvert a site's entire
Kerberos authentication infrastructure.

Kerberos version 5 does not contain this cryptographic
vulnerability.  Sites are not vulnerable if they have Kerberos v4
completely disabled, including the disabling of any krb5 to krb4
translation services.

. The MIT Kerberos 5 implementation includes an RPC library derived
from SUNRPC.  The implementation contains length checks, that are
vulnerable to an integer overflow, which may be exploitable to
create denials of service or to gain unauthorized access to
sensitive information.

. Buffer overrun and underrun problems exist in Kerberos principal
name handling in unusual cases, such as names with zero components,
names with one empty component, or host-based service principal
names with no host name component.

For the stable distribution (woody) this problem has been
fixed in version 1.2.4-5woody4.

The old stable distribution (potato) does not contain krb5 packages.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your krb5 package.";
tag_summary = "The remote host is missing an update to krb5
announced via advisory DSA 266-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20266-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303593");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0028", "CVE-2003-0072", "CVE-2003-0138", "CVE-2003-0139");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 266-1 (krb5)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.2.4-5woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
