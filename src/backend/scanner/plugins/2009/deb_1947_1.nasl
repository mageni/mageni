# OpenVAS Vulnerability Test
# $Id: deb_1947_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1947-1 (shibboleth-sp, shibboleth-sp2, opensaml2)
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
tag_insight = "Matt Elder discovered that Shibboleth, a federated web single sign-on
system is vulnerable to script injection through redirection URLs. More
details can be found in the Shibboleth advisory at
http://shibboleth.internet2.edu/secadv/secadv_20091104.txt

For the old stable distribution (etch), this problem has been fixed in
version 1.3f.dfsg1-2+etch2 of shibboleth-sp.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.1.dfsg1-3+lenny2 of shibboleth-sp, version 2.0.dfsg1-4+lenny2
of shibboleth-sp2 and version 2.0-2+lenny2 of opensaml2.

For the unstable distribution (sid), this problem has been fixed in
version 2.3+dfsg-1 of shibboleth-sp2, version 2.3-1 of opensaml2 and
version 1.3.1-1 of xmltooling.

We recommend that you upgrade your Shibboleth packages.";
tag_summary = "The remote host is missing an update to shibboleth-sp, shibboleth-sp2, opensaml2
announced via advisory DSA 1947-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201947-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307489");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
 script_cve_id("CVE-2009-3300");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1947-1 (shibboleth-sp, shibboleth-sp2, opensaml2)");



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
if ((res = isdpkgvuln(pkg:"libshib-dev", ver:"1.3f.dfsg1-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-target5", ver:"1.3f.dfsg1-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib6", ver:"1.3f.dfsg1-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-shib", ver:"1.3f.dfsg1-2+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml2-doc", ver:"2.0-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"opensaml2-schemas", ver:"2.0-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshibsp-doc", ver:"2.0.dfsg1-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"shibboleth-sp2-schemas", ver:"2.0.dfsg1-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-dev", ver:"1.3.1.dfsg1-3+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib6", ver:"1.3.1.dfsg1-3+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshib-target5", ver:"1.3.1.dfsg1-3+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-shib", ver:"1.3.1.dfsg1-3+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-shib2", ver:"2.0.dfsg1-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshibsp1", ver:"2.0.dfsg1-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libshibsp-dev", ver:"2.0.dfsg1-4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml2-dev", ver:"2.0-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"opensaml2-tools", ver:"2.0-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsaml2", ver:"2.0-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
