# OpenVAS Vulnerability Test
# $Id: deb_900_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 900-2
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge3.

For the unstable distribution (sid) this problem has been fixed in
version 6.2.5.4-1.

We recommend that you upgrade your fetchmail package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20900-2";
tag_summary = "The remote host is missing an update to fetchmail
announced via advisory DSA 900-2.

Due to restrictive dependency definition the updated fetchmailconf
package couldn't be installed on the old stable distribution (woody)
together with fetchmail-ssl.  Hence, this update loosens it, so that
the update can be pulled in.  For completeness we're including the
original advisory text:

Thomas Wolff discovered that the fetchmailconfig program which is
provided as part of fetchmail, an SSL enabled POP3, APOP, IMAP mail
gatherer/forwarder, creates the new configuration in an insecure
fashion that can lead to leaking passwords for mail accounts to
local users.

This update also fixes a regression in the package for stable caused
by the last security update.

For the old stable distribution (woody) this problem has been fixed in
version 5.9.11-6.4.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302932");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(15179);
 script_cve_id("CVE-2005-3088");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 900-2 (fetchmail)");



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
if ((res = isdpkgvuln(pkg:"fetchmail-common", ver:"5.9.11-6.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.9.11-6.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmail", ver:"5.9.11-6.4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
