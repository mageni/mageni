# OpenVAS Vulnerability Test
# $Id: deb_1551_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1551-1 (python2.4)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Several vulnerabilities have been discovered in the interpreter for the
Python language. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2007-2052

Piotr Engelking discovered that the strxfrm() function of the locale
module miscalculates the length of an internal buffer, which may
result in a minor information disclosure.

CVE-2007-4965

It was discovered that several integer overflows in the imageop
module may lead to the execution of arbitrary code, if a user is
tricked into processing malformed images. This issue is also
tracked as CVE-2008-1679 due to an initially incomplete patch.

CVE-2008-1721

Justin Ferguson discovered that a buffer overflow in the zlib
module may lead to the execution of arbitrary code.

CVE-2008-1887

Justin Ferguson discovered that insufficient input validation in
PyString_FromStringAndSize() may lead to the execution of arbitrary
code.

For the stable distribution (etch), these problems have been fixed in
version 2.4.4-3+etch1.

For the unstable distribution (sid), these problems have been fixed in
version 2.4.5-2.

We recommend that you upgrade your python2.4 packages.";
tag_summary = "The remote host is missing an update to python2.4
announced via advisory DSA 1551-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201551-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300717");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
 script_cve_id("CVE-2007-2052", "CVE-2007-4965", "CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1551-1 (python2.4)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4", ver:"2.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
