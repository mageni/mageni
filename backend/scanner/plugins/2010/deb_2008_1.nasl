# OpenVAS Vulnerability Test
# $Id: deb_2008_1.nasl 8207 2017-12-21 07:30:12Z teissa $
# Description: Auto-generated from advisory DSA 2008-1 (typo3-src)
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
tag_insight = "Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework: Cross-site scripting vulnerabilities have
been discovered in both the frontend and the backend. Also, user data
could be leaked. More details can be found in the Typo3 security
advisory:
http://typo3.org/teams/security/security-bulletins/typo3-sa-2010-004/

For the stable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny3.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version 4.3.2-1.

We recommend that you upgrade your typo3-src package.";
tag_summary = "The remote host is missing an update to typo3-src
announced via advisory DSA 2008-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202008-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313823");
 script_version("$Revision: 8207 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-03-16 17:25:39 +0100 (Tue, 16 Mar 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 2008-1 (typo3-src)");



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
if ((res = isdpkgvuln(pkg:"typo3-src-4.2", ver:"4.2.5-1+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.2.5-1+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
