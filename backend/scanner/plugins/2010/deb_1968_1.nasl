# OpenVAS Vulnerability Test
# $Id: deb_1968_1.nasl 8440 2018-01-17 07:58:46Z teissa $
# Description: Auto-generated from advisory DSA 1968-1 (pdns-recursor)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "It was discovered that pdns-recursor, the PowerDNS recursive name
server, contains several vulnerabilities:

A buffer overflow can be exploited to crash the daemon, or potentially
execute arbitrary code (CVE-2009-4009).

A cache poisoning vulnerability may allow attackers to trick the
server into serving incorrect DNS data (CVE-2009-4010).

For the old stable distribution (etch), fixed packages will be
provided soon.

For the stable distribution (lenny), these problems have been fixed in
version 3.1.7-1+lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 3.1.7.2-1.

We recommend that you upgrade your pdns-recursor package.";
tag_summary = "The remote host is missing an update to pdns-recursor
announced via advisory DSA 1968-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201968-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312787");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-20 20:07:43 +0100 (Wed, 20 Jan 2010)");
 script_cve_id("CVE-2009-4009", "CVE-2009-4010");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1968-1 (pdns-recursor)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"pdns-recursor", ver:"3.1.7-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
