# OpenVAS Vulnerability Test
# $Id: deb_2051_1.nasl 8528 2018-01-25 07:57:36Z teissa $
# Description: Auto-generated from advisory DSA 2051-1 (postgresql-8.3)
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
tag_insight = "Several local vulnerabilities have been discovered in PostgreSQL, an
object-relational SQL database. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2010-1169

Tim Bunce discovered that the implementation of the procedural
language PL/Perl insufficiently restricts the subset of allowed
code, which allows authenticated users the execution of arbitrary
Perl code.

CVE-2010-1170

Tom Lane discovered that the implementation of the procedural
language PL/Tcl insufficiently restricts the subset of allowed
code, which allows authenticated users the execution of arbitrary
Tcl code.

CVE-2010-1975

It was discovered that an unprivileged user could reset
superuser-only parameter settings.

For the stable distribution (lenny), these problems have been fixed in
version 8.3.11-0lenny1. This update also introduces a fix for
CVE-2010-0442, which was originally scheduled for the next Lenny point
update.

For the unstable distribution (sid), these problems have been fixed in
version 8.4.4-1 of postgresql-8.4.

We recommend that you upgrade your postgresql-8.3 packages.";
tag_summary = "The remote host is missing an update to postgresql-8.3
announced via advisory DSA 2051-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202051-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.315068");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2010-0442", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");
 script_name("Debian Security Advisory DSA 2051-1 (postgresql-8.3)");



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
if ((res = isdpkgvuln(pkg:"postgresql", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg6", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-8.3", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq5", ver:"8.3.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
