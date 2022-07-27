# OpenVAS Vulnerability Test
# $Id: deb_1858_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1858-1 (imagemagick)
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
tag_insight = "Several vulnerabilities have been discovered in the imagemagick image
manipulation programs which can lead to the execution of arbitrary code,
exposure of sensitive information or cause DoS. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2007-1667

Multiple integer overflows in XInitImage function in xwd.c for
ImageMagick, allow user-assisted remote attackers to cause a denial of
service (crash) or obtain sensitive information via crafted images with
large or negative values that trigger a buffer overflow. It only affects
the oldstable distribution (etch).

CVE-2007-1797

Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted DCM image, or the colors or comments field in a
crafted XWD image. It only affects the oldstable distribution (etch).

CVE-2007-4985

A crafted image file can trigger an infinite loop in the ReadDCMImage
function or in the ReadXCFImage function. It only affects the oldstable
distribution (etch).

CVE-2007-4986

Multiple integer overflows allow context-dependent attackers to execute
arbitrary code via a crafted .dcm, .dib, .xbm, .xcf, or .xwd image file,
which triggers a heap-based buffer overflow. It only affects the
oldstable distribution (etch).

CVE-2007-4987

Off-by-one error allows context-dependent attackers to execute arbitrary
code via a crafted image file, which triggers the writing of a '\0'
character to an out-of-bounds address. It affects only the oldstable
distribution (etch).

CVE-2007-4988

A sign extension error allows context-dependent attackers to execute
arbitrary code via a crafted width value in an image file, which
triggers an integer overflow and a heap-based buffer overflow. It
affects only the oldstable distribution (etch).

CVE-2008-1096

The load_tile function in the XCF coder allows user-assisted remote
attackers to cause a denial of service or possibly execute arbitrary
code via a crafted .xcf file that triggers an out-of-bounds heap write.
It affects only to oldstable (etch).

CVE-2008-1097

Heap-based buffer overflow in the PCX coder allows user-assisted remote
attackers to cause a denial of service or possibly execute arbitrary
code via a crafted .pcx file that triggers incorrect memory allocation
for the scanline array, leading to memory corruption. It affects only to
oldstable (etch).

CVE-2009-1882

Integer overflow allows remote attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a crafted TIFF file,
which triggers a buffer overflow.

For the old stable distribution (etch), these problems have been fixed in
version 7:6.2.4.5.dfsg1-0.15+etch1.

For the stable distribution (lenny), these problems have been fixed in
version 7:6.3.7.9.dfsg2-1~lenny3.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version
7:6.5.1.0-1.1.

We recommend that you upgrade your imagemagick packages.";
tag_summary = "The remote host is missing an update to imagemagick
announced via advisory DSA 1858-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201858-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309296");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_cve_id("CVE-2007-1667", "CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097", "CVE-2009-1882");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1858-1 (imagemagick)");



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
if ((res = isdpkgvuln(pkg:"libmagick++9c2a", ver:"6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9-dev", ver:"6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9", ver:"6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++10", ver:"6.3.7.9.dfsg2-1~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick9-dev", ver:"6.3.7.9.dfsg2-1~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick10", ver:"6.3.7.9.dfsg2-1~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"6.3.7.9.dfsg2-1~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"6.3.7.9.dfsg2-1~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"6.3.7.9.dfsg2-1~lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
