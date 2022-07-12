# OpenVAS Vulnerability Test
# $Id: deb_1515_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1515-1 (libnet-dns-perl)
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
tag_insight = "Several remote vulnerabilities have been discovered in libnet-dns-perl.
The Common Vulnerabilities and Exposures project identifies the
following problems:

It was discovered that libnet-dns-perl generates very weak transaction
IDs when sending queries (CVE-2007-3377).  This update switches
transaction ID generation to the Perl random generator, making
prediction attacks more difficult.

Compression loops in domain names resulted in an infinite loop in the
domain name expander written in Perl (CVE-2007-3409).  The Debian
package uses an expander written in C by default, but this vulnerability
has been addressed nevertheless.

Decoding malformed A records could lead to a crash (via an uncaught
Perl exception) of certain applications using libnet-dns-perl
(CVE-2007-6341).

For the stable distribution (etch), these problems have been fixed in
version 0.59-1etch1.

For the old stable distribution (sarge), these problems have been fixed in
version 0.48-1sarge1.

We recommend that you upgrade your libnet-dns-perl package.";
tag_summary = "The remote host is missing an update to libnet-dns-perl
announced via advisory DSA 1515-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201515-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302858");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-03-19 20:30:32 +0100 (Wed, 19 Mar 2008)");
 script_cve_id("CVE-2007-3377", "CVE-2007-3409", "CVE-2007-6341");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1515-1 (libnet-dns-perl)");



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
if ((res = isdpkgvuln(pkg:"libnet-dns-perl", ver:"0.48-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnet-dns-perl", ver:"0.59-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
