# OpenVAS Vulnerability Test
# $Id: deb_1746_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1746-1 (ghostscript)
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
tag_insight = "Two security issues have been discovered in ghostscript, the GPL
Ghostscript PostScript/PDF interpreter. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2009-0583

Jan Lieskovsky discovered multiple integer overflows in the ICC library,
which allow the execution of arbitrary code via crafted ICC profiles in
PostScript files with embedded images.

CVE-2009-0584

Jan Lieskovsky discovered insufficient upper-bounds checks on certain
variable sizes in the ICC library, which allow the execution of
arbitrary code via crafted ICC profiles in PostScript files with
embedded images.


For the stable distribution (lenny), these problems have been fixed in
version 8.62.dfsg.1-3.2lenny1.

For the oldstable distribution (etch), these problems have been fixed
in version 8.54.dfsg.1-5etch2. Please note that the package in oldstable
is called gs-gpl.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems will be fixed soon.

We recommend that you upgrade your ghostscript/gs-gpl packages.";
tag_summary = "The remote host is missing an update to ghostscript
announced via advisory DSA 1746-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201746-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306435");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2009-0583", "CVE-2009-0584");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1746-1 (ghostscript)");



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
if ((res = isdpkgvuln(pkg:"gs", ver:"8.54.dfsg.1-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.54.dfsg.1-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-common", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-doc", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-esp", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-gpl", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gs-aladdin", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs8", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ghostscript-x", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgs-dev", ver:"8.62.dfsg.1-3.2lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
