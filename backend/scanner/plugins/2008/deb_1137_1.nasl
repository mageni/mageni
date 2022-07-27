# OpenVAS Vulnerability Test
# $Id: deb_1137_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1137-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 3.7.2-7.

For the unstable distribution (sid) these problems have been fixed in
version 3.8.2-6.

We recommend that you upgrade your libtiff packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201137-1";
tag_summary = "The remote host is missing an update to tiff
announced via advisory DSA 1137-1.

Tavis Ormandy of the Google Security Team discovered several problems
in the TIFF library.  The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2006-3459

Several stack-buffer overflows have been discovered.

CVE-2006-3460

A heap overflow vulnerability in the JPEG decoder may overrun a
buffer with more data than expected.

CVE-2006-3461

A heap overflow vulnerability in the PixarLog decoder may allow an
attacker to execute arbitrary code.

CVE-2006-3462

A heap overflow vulnerability has been discovered in the NeXT RLE
decoder.

CVE-2006-3463

An loop was discovered where a 16bit unsigned short was used to
iterate over a 32bit unsigned value so that the loop would never
terminate and continue forever.

CVE-2006-3464

Multiple unchecked arithmetic operations were uncovered, including
a number of the range checking operations designed to ensure the
offsets specified in TIFF directories are legitimate.

CVE-2006-3465

A flaw was also uncovered in libtiffs custom tag support which may
result in abnormal behaviour, crashes, or potentially arbitrary
code execution.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302824");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1137-1 (tiff)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.7.2-7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.7.2-7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.7.2-7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.7.2-7", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0", ver:"3.7.2-7", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
