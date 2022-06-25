# OpenVAS Vulnerability Test
# $Id: deb_1239_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1239-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 2.4.7-2sarge1.

For the upcoming stable distribution (etch) these problems have been
fixed in version 2.6.21-1.

For the unstable distribution (sid) these problems have been fixed in
version 2.6.21-1.

We recommend that you upgrade your sql-ledger packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201239-1";
tag_summary = "The remote host is missing an update to sql-ledger
announced via advisory DSA 1239-1.

Several remote vulnerabilities have been discovered in SQL Ledger, a web
based double-entry accounting program, which may lead to the execution
of arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2006-4244

Chris Travers discovered that the session management can be tricked
into hijacking existing sessions.

CVE-2006-4731

Chris Travers discovered that directory traversal vulnerabilities
can be exploited to execute arbitrary Perl code.

CVE-2006-5872

It was discovered that missing input sanitising allows execution of
arbitrary Perl code.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301230");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-4244", "CVE-2006-4731", "CVE-2006-5872");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1239-1 (sql-ledger)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"sql-ledger", ver:"2.4.7-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
