# OpenVAS Vulnerability Test
# $Id: deb_1455_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1455-1 (libarchive1)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several local/remote vulnerabilities have been discovered in libarchive1,
a single library to read/write tar, cpio, pax, zip, iso9660, archives.

The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-3641

It was discovered that libarchive1 would miscompute the length of a buffer
resulting in a buffer overflow if yet another type of corruption occurred
in a pax extension header.

CVE-2007-3644

It was discovered that if an archive prematurely ended within a pax
extension header the libarchive1 library could enter an infinite loop.

CVE-2007-3645

If an archive prematurely ended within a tar header, immediately following
a pax extension header, libarchive1 could dereference a NULL pointer.


The old stable distribution (sarge), does not contain this package.

For the stable distribution (etch), these problems have been fixed in
version 1.2.53-2etch1.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.4-1.

We recommend that you upgrade your libarchive package.";
tag_summary = "The remote host is missing an update to libarchive1
announced via advisory DSA 1455-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201455-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303187");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-3641", "CVE-2007-3644", "CVE-2007-3645");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1455-1 (libarchive1)");



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
if ((res = isdpkgvuln(pkg:"libarchive-dev", ver:"1.2.53-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bsdtar", ver:"1.2.53-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarchive1", ver:"1.2.53-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
