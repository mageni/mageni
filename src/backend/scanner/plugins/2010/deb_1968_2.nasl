# OpenVAS Vulnerability Test
# $Id: deb_1968_2.nasl 8187 2017-12-20 07:30:09Z teissa $
# Description: Auto-generated from advisory DSA 1968-2 (pdns-recursor)
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
tag_insight = "It was discovered that pdns-recursor, the PowerDNS recursive name server,
contains a cache poisoning vulnerability which may allow attackers to trick the
server into serving incorrect DNS data (CVE-2009-4010).

This DSA provides a security update for the old stable distribution
(etch), similar to the previous update in DSA-1968-1.  (Note that the
etch version of pdns-recursor was not vulnerable to CVE-2009-4009.)

Extra care should be applied when installing this update.  It is an etch
backport of the lenny version of the package (3.1.7 with security fixes
applied). Major differences in internal domain name processing made
backporting just the security fix too difficult.

For the old stable distribution (etch), this problem has been fixed in
version 3.1.4+v3.1.7-0+etch1.

We recommend that you upgrade your pdns-recursor package.";
tag_summary = "The remote host is missing an update to pdns-recursor
announced via advisory DSA 1968-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201968-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314159");
 script_version("$Revision: 8187 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-02-01 18:25:19 +0100 (Mon, 01 Feb 2010)");
 script_cve_id("CVE-2009-4010", "CVE-2009-4009");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1968-2 (pdns-recursor)");



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
if ((res = isdpkgvuln(pkg:"pdns-recursor", ver:"3.1.4+v3.1.7-0+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
