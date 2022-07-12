# OpenVAS Vulnerability Test
# $Id: deb_213_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 213-1
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
tag_insight = "Glenn Randers-Pehrson discovered a problem in connection with 16-bit
samples from libpng, an interface for reading and writing PNG
(Portable Network Graphics) format files.  The starting offsets for
the loops are calculated incorrectly which causes a buffer overrun
beyond the beginning of the row buffer.

For the current stable distribution (woody) this problem has been
fixed in version 1.0.12-3.woody.3 for libpng and in version
1.2.1-1.1.woody.3 for libpng3.

For the old stable distribution (potato) this problem has been fixed
in version 1.0.5-1.1 for libpng.  There are no other libpng packages.

For the unstable distribution (sid) this problem has been fixed in
version 1.0.12-7 for libpng and in version 1.2.5-8 for libpng3.

We recommend that you upgrade your libpng packages.";
tag_summary = "The remote host is missing an update to libpng, libpng3
announced via advisory DSA 213-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20213-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300067");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(6431);
 script_cve_id("CVE-2002-1363");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 213-1 (libpng, libpng3)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libpng2", ver:"1.0.5-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng2-dev", ver:"1.0.5-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng2", ver:"1.0.12-3.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng2-dev", ver:"1.0.12-3.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng-dev", ver:"1.2.1-1.1.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.1-1.1.woody.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
