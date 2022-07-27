# OpenVAS Vulnerability Test
# $Id: deb_1595_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1595-1 (xorg-server)
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
tag_insight = "Several local vulnerabilities have been discovered in the X Window system.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2008-1377

Lack of validation of the parameters of the
SProcSecurityGenerateAuthorization SProcRecordCreateContext
functions makes it possible for a specially crafted request to trigger
the swapping of bytes outside the parameter of these requests, causing
memory corruption.

CVE-2008-1379

An integer overflow in the validation of the parameters of the
ShmPutImage() request makes it possible to trigger the copy of
arbitrary server memory to a pixmap that can subsequently be read by
the client, to read arbitrary parts of the X server memory space.

CVE-2008-2360

An integer overflow may occur in the computation of the size of the
glyph to be allocated by the AllocateGlyph() function which will cause
less memory to be allocated than expected, leading to later heap
overflow.

CVE-2008-2361

An integer overflow may occur in the computation of the  size of the
glyph to be allocated by the ProcRenderCreateCursor() function which
will cause less memory to be allocated than expected, leading later
to dereferencing un-mapped memory, causing a crash of the X server.

CVE-2008-2362

Integer overflows can also occur in the code validating the parameters
for the SProcRenderCreateLinearGradient, SProcRenderCreateRadialGradient
and SProcRenderCreateConicalGradient functions, leading to memory
corruption by swapping bytes outside of the intended request
parameters.

For the stable distribution (etch), these problems have been fixed in version
2:1.1.1-21etch5.

For the unstable distribution (sid), these problems have been fixed in
version 2:1.4.1~git20080517-2.

We recommend that you upgrade your xorg-server package.";
tag_summary = "The remote host is missing an update to xorg-server
announced via advisory DSA 1595-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201595-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301349");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-06-28 00:42:46 +0200 (Sat, 28 Jun 2008)");
 script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1595-1 (xorg-server)");



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
if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xephyr", ver:"1.1.1-21etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
