# OpenVAS Vulnerability Test
# $Id: deb_1896_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1896-1 (opensaml, shibboleth-sp)
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
tag_insight = "Several vulnerabilities have been discovered in the opensaml and
shibboleth-sp packages, as used by Shibboleth 1.x:

Chris Ries discovered that decoding a crafted URL leads to a crash
(and potentially, arbitrary code execution).

Ian Young discovered that embedded NUL characters in certificate names
were not correctly handled, exposing configurations using PKIX trust
validation to impersonation attacks.

Incorrect processing of SAML metadata ignored key usage constraints.

For the old stable distribution (etch), these problems have been fixed
in version 1.3f.dfsg1-2+etch1 of the shibboleth-sp packages, and
version 1.1a-2+etch1 of the opensaml packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.3.1.dfsg1-3+lenny1 of the shibboleth-sp packages, and
version 1.1.1-2+lenny1 of the opensaml packages.

The unstable distribution (sid) does not contain Shibboleth 1.x
packages.

This update requires restarting the affected services (mainly Apache)
to become effective.

We recommend that you upgrade your Shibboleth 1.x packages.";
tag_summary = "The remote host is missing an update to opensaml, shibboleth-sp
announced via advisory DSA 1896-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201896-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307811");
 script_cve_id("CVE-2009-3474","CVE-2009-3475");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1896-1 (opensaml, shibboleth-sp)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"opensaml-schemas", ver:"1.1a-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-shib", ver:"1.3f.dfsg1-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib6", ver:"1.3f.dfsg1-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml-dev", ver:"1.1a-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-dev", ver:"1.3f.dfsg1-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml5", ver:"1.1a-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-target5", ver:"1.3f.dfsg1-2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"opensaml-schemas", ver:"1.1.1-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-dev", ver:"1.3.1.dfsg1-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml5", ver:"1.1.1-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-shib", ver:"1.3.1.dfsg1-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib6", ver:"1.3.1.dfsg1-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml-dev", ver:"1.1.1-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-target5", ver:"1.3.1.dfsg1-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
