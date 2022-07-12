# OpenVAS Vulnerability Test
# $Id: deb_1770_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1770-1 (imp4)
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
tag_insight = "Several vulnerabilities have been found in imp4, a webmail component for
the horde framework. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-4182

It was discovered that imp4 suffers from a cross-site scripting (XSS)
attack via the user field in an IMAP session, which allows attackers to
inject arbitrary HTML code.

CVE-2009-0930

It was discovered that imp4 is prone to several cross-site scripting
(XSS) attacks via several vectors in the mail code allowing attackers
to inject arbitrary HTML code.

For the oldstable distribution (etch), these problems have been fixed in
version 4.1.3-4etch1.

For the stable distribution (lenny), these problems have been fixed in
version 4.2-4, which was already included in the lenny release.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 4.2-4.


We recommend that you upgrade your imp4 packages.";
tag_summary = "The remote host is missing an update to imp4
announced via advisory DSA 1770-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201770-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308793");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2008-4182", "CVE-2009-0930");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1770-1 (imp4)");



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
if ((res = isdpkgvuln(pkg:"imp4", ver:"4.1.3-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
