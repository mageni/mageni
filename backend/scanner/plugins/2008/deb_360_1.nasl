# OpenVAS Vulnerability Test
# $Id: deb_360_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 360-1
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
tag_insight = "xfstt, a TrueType font server for the X window system was found to
contain two classes of vulnerabilities:

- - CVE-2003-0581: a remote attacker could send requests crafted to
trigger any of several buffer overruns, causing a denial of service or
possibly executing arbitrary code on the server with the privileges
of the 'nobody' user.

- - CVE-2003-0625: certain invalid data sent during the connection
handshake could allow a remote attacker to read certain regions of
memory belonging to the xfstt process.  This information could be
used for fingerprinting, or to aid in exploitation of a different
vulnerability.

For the current stable distribution (woody) these problems have been
fixed in version 1.2.1-3.

For the unstable distribution (sid), CVE-2003-0581 is fixed in xfstt
1.5-1, and CVE-2003-0625 will be fixed soon.

We recommend that you update your xfstt package.";
tag_summary = "The remote host is missing an update to xfstt
announced via advisory DSA 360-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20360-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304052");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0581", "CVE-2003-0625");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 360-1 (xfstt)");



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
if ((res = isdpkgvuln(pkg:"xfstt", ver:"1.2.1-3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
