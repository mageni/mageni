# OpenVAS Vulnerability Test
# $Id: deb_1629_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1629-1 (postfix)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Sebastian Krahmer discovered that Postfix, a mail transfer agent,
incorrectly checks the ownership of a mailbox. In some configurations,
this allows for appending data to arbitrary files as root.

The default Debian installation of Postfix is not affected. Only a
configuration meeting the following requirements is vulnerable:
* The mail delivery style is mailbox, with the Postfix built-in
local(8) or virtual(8) delivery agents.
* The mail spool directory is user-writeable.
* The user can create hardlinks pointing to root-owned symlinks
located in other directories.

For a detailed treating of this issue, please refer to the upstream
author's announcement:
http://article.gmane.org/gmane.mail.postfix.announce/110

For the stable distribution (etch), this problem has been fixed in
version 2.3.8-2etch1.

For the testing distribution (lenny), this problem has been fixed in
version 2.5.2-2lenny1.

For the unstable distribution (sid), this problem has been fixed
in version 2.5.4-1.

We recommend that you upgrade your postfix package.";
tag_summary = "The remote host is missing an update to postfix
announced via advisory DSA 1629-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201629-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301739");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-04 17:00:42 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-2936");
 script_tag(name:"cvss_base", value:"6.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1629-1 (postfix)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"postfix-dev", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix-doc", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix-cdb", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix-mysql", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix-ldap", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix-pcre", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postfix-pgsql", ver:"2.3.8-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
