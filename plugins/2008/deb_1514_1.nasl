# OpenVAS Vulnerability Test
# $Id: deb_1514_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1514-1 (moin)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Several remote vulnerabilities have been discovered in MoinMoin, a
Python clone of WikiWiki. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2007-2423

A cross-site-scripting vulnerability has been discovered in
attachment handling.

CVE-2007-2637

Access control lists for calendars and includes were
insufficiently enforced, which could lead to information
disclosure.

CVE-2008-0780

A cross-site-scripting vulnerability has been discovered in
the login code.

CVE-2008-0781

A cross-site-scripting vulnerability has been discovered in
attachment handling.

CVE-2008-0782

A directory traversal vulnerability in cookie handling could
lead to local denial of service by overwriting files.

CVE-2008-1098

Cross-site-scripting vulnerabilities have been discovered in
the GUI editor formatter and the code to delete pages.

CVE-2008-1099

The macro code validates access control lists insufficiently,
which could lead to information disclosure.


For the stable distribution (etch), these problems have been fixed in
version 1.5.3-1.2etch1. This update also includes a bugfix wrt the
encoding of password reminder mails, which doesn't have security
implications.

The old stable distribution (sarge) will not be updated due to
the many changes and support for Sarge ending end of this month
anyway. You're advised to upgrade to the stable distribution if
you run moinmoin.

We recommend that you upgrade your moin package.";
tag_summary = "The remote host is missing an update to moin
announced via advisory DSA 1514-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201514-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302031");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-03-11 21:16:32 +0100 (Tue, 11 Mar 2008)");
 script_cve_id("CVE-2007-2423", "CVE-2007-2637", "CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_name("Debian Security Advisory DSA 1514-1 (moin)");



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
if ((res = isdpkgvuln(pkg:"moinmoin-common", ver:"1.5.3-1.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.3-1.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
