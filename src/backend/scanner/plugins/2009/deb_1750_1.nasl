# OpenVAS Vulnerability Test
# $Id: deb_1750_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1750-1 (libpng)
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
tag_insight = "Several vulnerabilities have been discovered in libpng, a library for
reading and writing PNG files. The Common Vulnerabilities and
Exposures project identifies the following problems:

The png_handle_tRNS function allows attackers to cause a denial of
service (application crash) via a grayscale PNG image with a bad tRNS
chunk CRC value. (CVE-2007-2445)

Certain chunk handlers allow attackers to cause a denial of service
(crash) via crafted pCAL, sCAL, tEXt, iTXt, and ztXT chunking in PNG
images, which trigger out-of-bounds read operations. (CVE-2007-5269)

libpng allows context-dependent attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a PNG file with zero
length unknown chunks, which trigger an access of uninitialized
memory. (CVE-2008-1382)

The png_check_keyword might allow context-dependent attackers to set the
value of an arbitrary memory location to zero via vectors involving
creation of crafted PNG files with keywords. (CVE-2008-5907)

A memory leak in the png_handle_tEXt function allows context-dependent
attackers to cause a denial of service (memory exhaustion) via a crafted
PNG file. (CVE-2008-6218)

libpng allows context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted PNG
file that triggers a free of an uninitialized pointer in (1) the
png_read_png function, (2) pCAL chunk handling, or (3) setup of 16-bit
gamma tables. (CVE-2009-0040)

For the old stable distribution (etch), these problems have been fixed
in version1.2.15~beta5-1+etch2.

For the stable distribution (lenny), these problems have been fixed in
version 1.2.27-2+lenny2.  (Only CVE-2008-5907, CVE-2008-5907 and
CVE-2009-0040 affect the stable distribution.)

For the unstable distribution (sid), these problems have been fixed in
version 1.2.35-1.

We recommend that you upgrade your libpng packages.";
tag_summary = "The remote host is missing an update to libpng
announced via advisory DSA 1750-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201750-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308740");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2007-2445", "CVE-2007-5269", "CVE-2008-1382", "CVE-2008-5907", "CVE-2008-6218", "CVE-2009-0040");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1750-1 (libpng)");



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
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.15~beta5-1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.15~beta5-1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.15~beta5-1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.27-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.27-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.27-2+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
