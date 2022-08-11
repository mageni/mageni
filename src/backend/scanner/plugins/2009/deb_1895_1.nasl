# OpenVAS Vulnerability Test
# $Id: deb_1895_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1895-1 (xmltooling)
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
tag_insight = "Several vulnerabilities have been discovered in the xmltooling packages,
as used by Shibboleth:

Chris Ries discovered that decoding a crafted URL leads to a crash (and
potentially, arbitrary code execution).

Ian Young discovered that embedded NUL characters in certificate names
were not correctly handled, exposing configurations using PKIX trust
validation to impersonation attacks.

Incorrect processing of SAML metadata ignores key usage constraints.
This minor issue also needs a correction in the opensaml2 packages,
which will be provided in an upcoming stable point release (and,
before that, via stable-proposed-updates).

For the stable distribution (lenny), these problems have been fixed in
version 1.0-2+lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 1.2.2-1.

We recommend that you upgrade your xmltooling packages.";
tag_summary = "The remote host is missing an update to xmltooling
announced via advisory DSA 1895-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201895-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305390");
 script_cve_id("CVE-2009-3474","CVE-2009-3475");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1895-1 (xmltooling)");



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
if ((res = isdpkgvuln(pkg:"xmltooling-schemas", ver:"1.0-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmltooling-doc", ver:"1.0-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmltooling-dev", ver:"1.0-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxmltooling1", ver:"1.0-2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
