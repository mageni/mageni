# OpenVAS Vulnerability Test
# $Id: deb_1877_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1877-1 (mysql-dfsg-5.0)
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
tag_insight = "In MySQL 4.0.0 through 5.0.83, multiple format string vulnerabilities
in the dispatch_command() function in libmysqld/sql_parse.cc in mysqld
allow remote authenticated users to cause a denial of service (daemon
crash) and potentially the execution of arbitrary code via format
string specifiers in a database name in a COM_CREATE_DB or
COM_DROP_DB request.

For the stable distribution (lenny), this problem has been fixed in
version 5.0.51a-24+lenny2.

For the old stable distribution (etch), this problem has been fixed in
version 5.0.32-7etch11.

We recommend that you upgrade your mysql packages.";
tag_summary = "The remote host is missing an update to mysql-dfsg-5.0
announced via advisory DSA 1877-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201877-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311995");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2009-2446");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1877-1 (mysql-dfsg-5.0)");



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
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"5.0.32-7etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-common", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mysql-client-5.0", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmysqlclient15-dev", ver:"5.0.51a-24+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
