# OpenVAS Vulnerability Test
# $Id: deb_1843_1.nasl 8972 2018-02-28 07:02:10Z cfischer $
# Description: Auto-generated from advisory DSA 1843-1 (squid3)
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
tag_insight = "It was discovered that squid3, a high-performance proxy caching server for
web clients, is prone to several denial of service attacks.  Due to incorrect
bounds checking and insufficient validation while processing response and
request data an attacker is able to crash the squid daemon via crafted
requests or responses.


The squid package in the oldstable distribution (etch) is not affected
by this problem.

For the stable distribution (lenny), this problem has been fixed in
version 3.0.STABLE8-3+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid),
this problem will be fixed soon.


We recommend that you upgrade your squid3 packages.";
tag_summary = "The remote host is missing an update to squid3
announced via advisory DSA 1843-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201843-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306340");
 script_version("$Revision: 8972 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-28 08:02:10 +0100 (Wed, 28 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1843-1 (squid3)");
 script_cve_id("CVE-2009-2621", "CVE-2009-2622");

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
if ((res = isdpkgvuln(pkg:"squid3-common", ver:"3.0.STABLE8-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid3-cgi", ver:"3.0.STABLE8-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squidclient", ver:"3.0.STABLE8-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid3", ver:"3.0.STABLE8-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
