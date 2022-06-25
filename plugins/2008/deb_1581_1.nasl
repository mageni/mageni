# OpenVAS Vulnerability Test
# $Id: deb_1581_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1581-1 (gnutls13)
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
tag_insight = "Several remote vulnerabilities have been discovered in GNUTLS, an
implementation of the SSL/TLS protocol suite.

NOTE: The libgnutls13 package, which provides the GNUTLS library, does
not contain logic to automatically restart potentially affected
services.  You must restart affected services manually (mainly Exim,
using /etc/init.d/exim4 restart) after applying the update, to make
the changes fully effective.  Alternatively, you can reboot the system.

The following vulnerabilities have been identified:

A pre-authentication heap overflow involving oversized session
resumption data may lead to arbitrary code execution (CVE-2008-1948).

Repeated client hellos may result in a pre-authentication denial of
service condition due to a null pointer dereference (CVE-2008-1949).

Decoding cipher padding with an invalid record length may cause GNUTLS
to read memory beyond the end of the received record, leading to a
pre-authentication denial of service condition (CVE-2008-1950).

For the stable distribution (etch), these problems have been fixed in
version 1.4.4-3+etch1.  (Builds for the arm architecture are currently
not available and will be released later.)

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your GNUTLS packages.";
tag_summary = "The remote host is missing an update to gnutls13
announced via advisory DSA 1581-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201581-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301865");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-05-27 15:41:50 +0200 (Tue, 27 May 2008)");
 script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1581-1 (gnutls13)");



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
if ((res = isdpkgvuln(pkg:"gnutls-doc", ver:"1.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls13", ver:"1.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls13-dbg", ver:"1.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"1.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"1.4.4-3+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
