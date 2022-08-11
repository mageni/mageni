# OpenVAS Vulnerability Test
# $Id: deb_707_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 707-1
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
tag_insight = "Several vulnerabilities have been discovered in MySQL, a popular
database.  The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2004-0957

Sergei Golubchik discovered a problem in the access handling for
similar named databases.  If a user is granted privileges to a
database with a name containing an underscore (_), the user also
gains privileges to other databases with similar names.

CVE-2005-0709

Stefano Di Paola discovered that MySQL allows remote
authenticated users with INSERT and DELETE privileges to execute
arbitrary code by using CREATE FUNCTION to access libc calls.

CVE-2005-0710

Stefano Di Paola discovered that MySQL allows remote authenticated
users with INSERT and DELETE privileges to bypass library path
restrictions and execute arbitrary libraries by using INSERT INTO
to modify the mysql.func table.

CVE-2005-0711

Stefano Di Paola discovered that MySQL uses predictable file names
when creating temporary tables, which allows local users with
CREATE TEMPORARY TABLE privileges to overwrite arbitrary files via
a symlink attack.

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.11.

For the unstable distribution (sid) these problems have been fixed in
version 4.0.24-5 of mysql-dfsg and in version 4.1.10a-6 of
mysql-dfsg-4.1.

We recommend that you upgrade your mysql packages.";
tag_summary = "The remote host is missing an update to mysql
announced via advisory DSA 707-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20707-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301760");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0957", "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 script_bugtraq_id(12781);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 707-1 (mysql)");



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
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"3.23.49-8.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-doc", ver:"3.23.49-8.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10", ver:"3.23.49-8.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient10-dev", ver:"3.23.49-8.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"3.23.49-8.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"3.23.49-8.11", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
