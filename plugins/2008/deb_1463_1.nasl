# OpenVAS Vulnerability Test
# $Id: deb_1463_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1463-1 (postgresql-7.4)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several local vulnerabilities have been discovered in PostgreSQL, an
object-relational SQL database. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2007-3278

It was discovered that the DBLink module performed insufficient
credential validation. This issue is also tracked as CVE-2007-6601,
since the initial upstream fix was incomplete.

CVE-2007-4769

Tavis Ormandy and Will Drewry discovered that a bug in the handling
of back-references inside the regular expressions engine could lead
to an out of bands read, resulting in a crash. This constitutes only
a security problem if an application using ProgreSQL processes
regular expressions from untrusted sources.

CVE-2007-4772

Tavis Ormandy and Will Drewry discovered that the optimizer for regular
expression could be tricked into an infinite loop, resulting in denial
of service. This constitutes only a security problem if an application
using ProgreSQL processes regular expressions from untrusted sources.

CVE-2007-6067

Tavis Ormandy and Will Drewry discovered that the optimizer for regular
expression could be tricked massive ressource consumption. This
constitutes only a security problem if an application using ProgreSQL
processes regular expressions from untrusted sources.

CVE-2007-6600

Functions in index expressions could lead to privilege escalation. For
a more in depth explanation please see the upstream announce available
at http://www.postgresql.org/about/news.905.

The unstable distribution (sid) no longer contains postgres-7.4

For the stable distribution (etch), these problems have been fixed in
version 7.4.19-0etch1.

For the old stable distribution (sarge), some of these problems have been
fixed in version 7.4.7-6sarge6 of the postgresql package. Please note that
the fix for CVE-2007-6600 and for the handling of regular expressions
hasn't been backported due to the intrusiveness of the fix. We recommend
to upgrade to the stable distribution if these vulnerabilities affect your
setup.

We recommend that you upgrade your postgresql-7.4 packages.";
tag_summary = "The remote host is missing an update to postgresql-7.4
announced via advisory DSA 1463-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201463-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300610");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1463-1 (postgresql-7.4)");



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
if ((res = isdpkgvuln(pkg:"postgresql-doc", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpq3", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtcl-dev", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-dev", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpgtcl", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg4", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecpg-dev", ver:"7.4.7-6sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-doc-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-server-dev-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plpython-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-plperl-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-pltcl-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-client-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"postgresql-contrib-7.4", ver:"7.4.19-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
