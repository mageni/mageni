# OpenVAS Vulnerability Test
# $Id: deb_1935_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1935-1 (gnutls13 gnutls26)
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
tag_insight = "Dan Kaminsky and Moxie Marlinspike discovered that gnutls, an implementation of
the TLS/SSL protocol, does not properly handle a '\0' character in a domain name
in the subject's Common Name or Subject Alternative Name (SAN) field of an X.509
certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL
servers via a crafted certificate issued by a legitimate Certification
Authority. (CVE-2009-2730)

In addition, with this update, certificates with MD2 hash signatures are no
longer accepted since they're no longer considered cryptograhically secure. It
only affects the oldstable distribution (etch).(CVE-2009-2409)

For the oldstable distribution (etch), these problems have been fixed in version
1.4.4-3+etch5 for gnutls13.

For the stable distribution (lenny), these problems have been fixed in version
2.4.2-6+lenny2 for gnutls26.

For the testing distribution (squeeze), and the  unstable distribution (sid),
these problems have been fixed in version 2.8.3-1 for gnutls26.

We recommend that you upgrade your gnutls13/gnutls26 packages.";
tag_summary = "The remote host is missing an update to gnutls13 gnutls26
announced via advisory DSA 1935-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201935-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306796");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2009-2409", "CVE-2009-2730");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1935-1 (gnutls13 gnutls26)");



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
if ((res = isdpkgvuln(pkg:"gnutls-doc", ver:"1.4.4-3+etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"1.4.4-3+etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"1.4.4-3+etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls13", ver:"1.4.4-3+etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls13-dbg", ver:"1.4.4-3+etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-doc", ver:"2.4.2-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.4.2-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.4.2-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.4.2-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.4.2-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.4.2-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
