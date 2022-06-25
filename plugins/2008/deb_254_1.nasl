# OpenVAS Vulnerability Test
# $Id: deb_254_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 254-1
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
tag_insight = "A vulnerability has been discovered in NANOG traceroute, an enhanced
version of the Van Jacobson/BSD traceroute program.  A buffer overflow
occurs in the 'get_origin()' function.  Due to insufficient bounds
checking performed by the whois parser, it may be possible to corrupt
memory on the system stack.  This vulnerability can be exploited by a
remote attacker to gain root privileges on a target host.  Though,
most probably not in Debian.

The Common Vulnerabilities and Exposures (CVE) project additionally
identified the following vulnerabilities which were already fixed in
the Debian version in stable (woody) and oldstable (potato) and are
mentioned here for completeness (and since other distributions had to
release a separate advisory for them):

* CVE-2002-1364 (BugTraq ID 6166) talks about a buffer overflow in
the get_origin function which allows attackers to execute arbitrary
code via long WHOIS responses.

* CVE-2002-1051 (BugTraq ID 4956) talks about a format string
vulnerability that allows local users to execute arbitrary code via
the -T (terminator) command line argument.

* CVE-2002-1386 talks about a buffer overflow that may allow local
users to execute arbitrary code via a long hostname argument.

* CVE-2002-1387 talks about the spray mode that may allow local users
to overwrite arbitrary memory locations.

Fortunately, the Debian package drops privileges quite early after
startup, so those problems aer not likely to result in an exploit on a
Debian machine.

For the current stable distribution (woody) the above problem has been
fixed in version 6.1.1-1.2.

For the old stable distribution (potato) the above problem has been
fixed in version 6.0-2.2.

For the unstable distribution (sid) these problems have been fixed in
version 6.3.0-1.

We recommend that you upgrade your traceroute-nanog package.";
tag_summary = "The remote host is missing an update to traceroute-nanog
announced via advisory DSA 254-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20254-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301465");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1051", "CVE-2002-1364", "CVE-2002-1386", "CVE-2002-1387");
 script_bugtraq_id(4956,6166,6274,6275);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 254-1 (traceroute-nanog)");



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
if ((res = isdpkgvuln(pkg:"traceroute-nanog", ver:"6.0-2.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"traceroute-nanog", ver:"6.1.1-1.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
