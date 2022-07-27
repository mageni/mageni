# OpenVAS Vulnerability Test
# $Id: deb_771_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 771-1
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
version 2.9.17-13sarge1.

For the unstable distribution (sid) these problems have been fixed in
version 2.9.18-1.

We recommend that you upgrade your pdns package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20771-1";
tag_summary = "The remote host is missing an update to pdns
announced via advisory DSA 771-1.

Several problems have been discovered in pdns, a versatile nameserver
that can lead to a denial of service.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2005-2301

Norbert Sendetzky and Jan de Groot discoverd that the LDAP backend
did not properly escape all queries, allowing it to fail and not
answer queries anymore.

CVE-2005-2302

Wilco Baan discovered that queries from clients without recursion
permission can temporarily blank out domains to clients with
recursion permitted.  This enables outside users to blank out a
domain temporarily to normal users.

The old stable distribution (woody) does not contain pdns packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301419");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2301", "CVE-2005-2302");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 771-1 (pdns)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"pdns-doc", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-backend-geo", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-backend-sqlite", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-recursor", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pdns-server", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
