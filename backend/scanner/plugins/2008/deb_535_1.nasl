# OpenVAS Vulnerability Test
# $Id: deb_535_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 535-1
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
tag_insight = "Four vulnerabilities were discovered in squirrelmail:

CVE-2004-0519 - Multiple cross-site scripting (XSS) vulnerabilities
in SquirrelMail 1.4.2 allow remote attackers to execute arbitrary
script as other users and possibly steal authentication information
via multiple attack vectors, including the mailbox parameter in
compose.php.

CVE-2004-0520 - Cross-site scripting (XSS) vulnerability in mime.php
for SquirrelMail before 1.4.3 allows remote attackers to insert
arbitrary HTML and script via the content-type mail header, as
demonstrated using read_body.php.

CVE-2004-0521 - SQL injection vulnerability in SquirrelMail before
1.4.3 RC1 allows remote attackers to execute unauthorized SQL
statements, with unknown impact, probably via abook_database.php.

CVE-2004-0639 - Multiple cross-site scripting (XSS) vulnerabilities
in Squirrelmail 1.2.10 and earlier allow remote attackers to inject
arbitrary HTML or script via (1) the $mailer variable in
read_body.php, (2) the $senderNames_part variable in
mailbox_display.php, and possibly other vectors including (3) the
$event_title variable or (4) the $event_text variable.

For the current stable distribution (woody), these problems have been
fixed in version 1:1.2.6-1.4.

For the unstable distribution (sid), these problems have been fixed in
2:1.4.3a-0.1 and earlier versions.

We recommend that you update your squirrelmail package.";
tag_summary = "The remote host is missing an update to squirrelmail
announced via advisory DSA 535-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20535-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302132");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521", "CVE-2004-0639");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 535-1 (squirrelmail)");



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
if ((res = isdpkgvuln(pkg:"squirrelmail", ver:"1.2.6-1.4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
