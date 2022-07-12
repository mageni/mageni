# OpenVAS Vulnerability Test
# $Id: deb_165_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 165-1
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
tag_insight = "Mordred Labs and others found several vulnerabilities in PostgreSQL,
an object-relational SQL database.  They are inherited from several
buffer overflows and integer overflows.  Specially crafted long date
and time input, currency, repeat data and long timezone names could
cause the PostgreSQL server to crash as well as specially crafted
input data for lpad() and rpad().  More buffer/integer overflows were
found in circle_poly(), path_encode() and path_addr().

Except for the last three, these problems are fixed in the upstream
release 7.2.2 of PostgreSQL which is the recommended version to use.

Most of these problems do not exist in the version of PostgreSQL that
Debian ships in the potato release since the corresponding
functionality is not yet implemented.  However, PostgreSQL 6.5.3 is
quite old and may bear more risks than we are aware of, which may
include further buffer overflows, and certainly include bugs that
threaten the integrity of your data.

You are strongly advised not to use this release but to upgrade your
system to Debian 3.0 (stable) including PostgreSQL release 7.2.1
instead, where many bugs have been fixed and new features introduced
to increase compatibility with the SQL standards.

If you consider an upgrade, please make sure to dump the entire
database system using the pg_dumpall utility.  Please take into
consideration that the newer PostgreSQL is more strict in its input
handling.  This means that tests line foo = NULL which are not valid
won't be accepted anymore.  It also means that when using UNICODE
encoding, ISO 8859-1 and ISO 8859-15 are no longer valid incoding to
use when inserting data into the relation.  In such a case you are
advised to convert the dump in question using recode latin1..utf-16.

These problems have been fixed in version 7.2.1-2woody2 for the
current stable distribution (woody) and in version 7.2.2-2 for the
unstable distribution (sid).  The old stable distribution (potato) is
partially affected and we ship a fixed version 6.5.3-27.2 for it.

We recommend that you upgrade your PostgreSQL packages.";
tag_summary = "The remote host is missing an update to postgresql
announced via advisory DSA 165-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20165-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302083");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0972");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 165-1 (postgresql)");



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
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"6.5.3-27.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"6.5.3-27.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"6.5.3-27.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"6.5.3-27.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-dev", ver:"6.5.3-27.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"7.2.1-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"7.2.1-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"7.2.1-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"7.2.1-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-dev", ver:"7.2.1-2woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
