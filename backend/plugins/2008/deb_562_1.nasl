# OpenVAS Vulnerability Test
# $Id: deb_562_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 562-1
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
tag_insight = "Severl problems have been discovered in MySQL, a commonly used SQL
database on Unix servers.  The following problems have been identified
by the Common Vulnerabilities and Exposures Project:

CVE-2004-0835

Oleksandr Byelkin noticed that ALTER TABLE ... RENAME checks
CREATE/INSERT rights of the old table instead of the new one.

CVE-2004-0836

Lukasz Wojtow noticed a buffer overrun in the mysql_real_connect
function.

CVE-2004-0837

Dean Ellis noticed that multiple threads ALTERing the same (or
different) MERGE tables to change the UNION can cause the server
to crash or stall.

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.8.

For the unstable distribution (sid) these problems have been fixed in
version 4.0.21-1.

We recommend that you upgrade your mysql and related packages and";
tag_summary = "The remote host is missing an update to mysql
announced via advisory DSA 562-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20562-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300421");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 562-1 (mysql)");



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
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.23.49-8.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.8", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
