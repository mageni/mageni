# OpenVAS Vulnerability Test
# $Id: deb_1903_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1903-1 (graphicsmagick)
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
tag_insight = "Several vulnerabilities have been discovered in graphicsmagick, a
collection of image processing tool, which can lead to the execution
of arbitrary code, exposure of sensitive information or cause DoS.
For details on the issuess addressed, please visit the referenced
security advisories.

For the oldstable distribution (etch), these problems have been fixed in
version 1.1.7-13+etch1.

For the stable distribution (lenny), these problems have been fixed in
version 1.1.11-3.2+lenny1.

For the upcoming stable distribution (squeeze) and the unstable
distribution ion (sid), these problems have been fixed in version
1.3.5-5.1.

We recommend that you upgrade your graphicsmagick packages.";
tag_summary = "The remote host is missing an update to graphicsmagick
announced via advisory DSA 1903-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201903-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308627");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
 script_cve_id("CVE-2007-1667", "CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-3134", "CVE-2008-6070", "CVE-2008-6071", "CVE-2008-6072", "CVE-2008-6621", "CVE-2009-1882");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1903-1 (graphicsmagick)");



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
if ((res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick1", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick++1", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.1.7-13+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick++1", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick1", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.1.11-3.2+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
