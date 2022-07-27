# OpenVAS Vulnerability Test
# $Id: deb_654_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 654-1
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
tag_insight = "Erik Sjölund has discovered several security relevant problems in
enscript, a program to convert ASCII text into Postscript and other
formats.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:

CVE-2004-1184

Unsanitised input can cause the execution of arbitrary commands
via EPSF pipe support.  This has been disabled, also upstream.

CVE-2004-1185

Due to missing sanitising of filenames it is possible that a
specially crafted filename can cause arbitrary commands to be
executed.

CVE-2004-1186

Multiple buffer overflows can cause the program to crash.

Usually, enscript is only run locally, but since it is executed inside
of viewcvs some of the problems mentioned above can easily be turned
into a remote vulnerability.

For the stable distribution (woody) these problems have been fixed in
version 1.6.3-1.3.

For the unstable distribution (sid) these problems have been fixed in
version 1.6.4-6.

We recommend that you upgrade your enscript package.";
tag_summary = "The remote host is missing an update to enscript
announced via advisory DSA 654-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20654-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301792");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 654-1 (enscript)");



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
if ((res = isdpkgvuln(pkg:"enscript", ver:"1.6.3-1.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
