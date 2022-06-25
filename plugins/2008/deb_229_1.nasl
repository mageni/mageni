# OpenVAS Vulnerability Test
# $Id: deb_229_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 229-1
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
tag_insight = "Jouko Pynnonen discovered a probem with IMP, a web based IMAP mail
program.  Using carefully crafted URLs a remote attacker is able to
inject SQL code into SQL queries without proper user authentication.
Even though results of SQL queries aren't directly readable from the
screen, an attacker might. update his mail signature to contain wanted
query results and then view it on the preferences page of IMP.

The impact of SQL injection depends heavily on the underlying database
and its configuration.  If PostgreSQL is used, it's possible to
execute multiple complete SQL queries separated by semicolons.  The
database contains session id's so the attacker might hijack sessions
of people currently logged in and read their mail.  In the worst case,
if the hordemgr user has the required privilege to use the COPY SQL
command (found in PostgreSQL at least), a remote user may read or
write to any file the database user (postgres) can.  The attacker may
then be able to run arbitrary shell commands by writing them to the
postgres user's ~/.psqlrc; they'd be run when the user starts the psql
command which under some configurations happens regularly from a cron
script.

For the current stable distribution (woody) this problem has been
fixed in version 2.2.6-5.1.

For the old stable distribution (potato) this problem has been
fixed in version 2.2.6-0.potato.5.1.

For the unstable distribution (sid) these problems have been fixed in
version 2.2.6-7.

We recommend that you upgrade your IMP packages.";
tag_summary = "The remote host is missing an update to imp
announced via advisory DSA 229-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20229-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301685");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0025");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 229-1 (imp)");



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
if ((res = isdpkgvuln(pkg:"imp", ver:"2.2.6-0.potato.5.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imp", ver:"2.2.6-5.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
