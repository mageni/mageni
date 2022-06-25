# OpenVAS Vulnerability Test
# $Id: deb_2057_1.nasl 8187 2017-12-20 07:30:09Z teissa $
# Description: Auto-generated from advisory DSA 2057-1 (mysql-dfsg-5.0)
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
tag_insight = "Several vulnerabilities have been discovered in the MySQL
database server.
The Common Vulnerabilities and Exposures project identifies the
following problems:


CVE-2010-1626

MySQL allows local users to delete the data and index files of another
user's MyISAM table via a symlink attack in conjunction with the DROP
TABLE command.


CVE-2010-1848

MySQL failed to check the table name argument of a COM_FIELD_LIST
command packet for validity and compliance to acceptable table name
standards. This allows an authenticated user with SELECT privileges on
one table to obtain the field definitions of any table in all other
databases and potentially of other MySQL instances accessible from the
server's file system.


CVE-2010-1849

MySQL could be tricked to read packets indefinitely if it received a
packet larger than the maximum size of one packet.
This results in high CPU usage and thus denial of service conditions.


CVE-2010-1850

MySQL was susceptible to a buffer-overflow attack due to a
failure to perform bounds checking on the table name argument of a
COM_FIELD_LIST command packet. By sending long data for the table
name, a buffer is overflown, which could be exploited by an
authenticated user to inject malicious code.


For the stable distribution (lenny), these problems have been fixed in
version 5.0.51a-24+lenny4

The testing (squeeze) and unstable (sid) distribution do not contain
mysql-dfsg-5.0 anymore.

We recommend that you upgrade your mysql-dfsg-5.0 package.";
tag_summary = "The remote host is missing an update to mysql-dfsg-5.0
announced via advisory DSA 2057-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202057-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312918");
 script_version("$Revision: 8187 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-06-10 21:49:43 +0200 (Thu, 10 Jun 2010)");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
 script_name("Debian Security Advisory DSA 2057-1 (mysql-dfsg-5.0)");



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
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.51a-24+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
