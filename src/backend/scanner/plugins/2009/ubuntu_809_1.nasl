# OpenVAS Vulnerability Test
# $Id: ubuntu_809_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_809_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-809-1 (gnutls26)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libgnutls12                     1.2.9-2ubuntu1.7

Ubuntu 8.04 LTS:
  libgnutls13                     2.0.4-1ubuntu2.6

Ubuntu 8.10:
  libgnutls26                     2.4.1-1ubuntu0.4

Ubuntu 9.04:
  libgnutls26                     2.4.2-6ubuntu0.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-809-1";

tag_insight = "Moxie Marlinspike and Dan Kaminsky independently discovered that GnuTLS did
not properly handle certificates with NULL characters in the certificate
name. An attacker could exploit this to perform a man in the middle attack
to view sensitive information or alter encrypted communications.
(CVE-2009-2730)

Dan Kaminsky discovered GnuTLS would still accept certificates with MD2
hash signatures. As a result, an attacker could potentially create a
malicious trusted certificate to impersonate another site. This issue only
affected Ubuntu 6.06 LTS and Ubuntu 8.10. (CVE-2009-2409)

USN-678-1 fixed a vulnerability and USN-678-2 a regression in GnuTLS. The
 upstream patches introduced a regression when validating certain certificate
 chains that would report valid certificates as untrusted. This update
 fixes the problem, and only affected Ubuntu 6.06 LTS and Ubuntu 8.10 (Ubuntu
 8.04 LTS and 9.04 were fixed at an earlier date). In an effort to maintain a
 strong security stance and address all known regressions, this update
 deprecates X.509 validation chains using MD2 and MD5 signatures. To accommodate
 sites which must still use a deprected RSA-MD5 certificate, GnuTLS has been
 updated to stop looking when it has found a trusted intermediary certificate.
 This new handling of intermediary certificates is in accordance with other SSL
 implementations.

Original advisory details:

 Martin von Gagern discovered that GnuTLS did not properly verify
 certificate chains when the last certificate in the chain was self-signed.
 If a remote attacker were able to perform a man-in-the-middle attack, this
 flaw could be exploited to view sensitive information. (CVE-2008-4989)";
tag_summary = "The remote host is missing an update to gnutls26
announced via advisory USN-809-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308561");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-2409", "CVE-2009-2730", "CVE-2008-4989");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Ubuntu USN-809-1 (gnutls26)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-809-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"1.2.9-2ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls12", ver:"1.2.9-2ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"1.2.9-2ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls12-dbg", ver:"1.2.9-2ubuntu1.7", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-doc", ver:"2.0.4-1ubuntu2.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.0.4-1ubuntu2.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls13-dbg", ver:"2.0.4-1ubuntu2.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls13", ver:"2.0.4-1ubuntu2.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutlsxx13", ver:"2.0.4-1ubuntu2.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.0.4-1ubuntu2.6", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-doc", ver:"2.4.1-1ubuntu0.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.4.1-1ubuntu0.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.4.1-1ubuntu0.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.4.1-1ubuntu0.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.4.1-1ubuntu0.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.4.1-1ubuntu0.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-doc", ver:"2.4.2-6ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.4.2-6ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.4.2-6ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.4.2-6ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.4.2-6ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.4.2-6ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
