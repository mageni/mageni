# OpenVAS Vulnerability Test
# $Id: deb_666_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 666-1
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
tag_insight = "The Python development team has discovered a flaw in their language
packge.  The SimpleXMLRPCServer library module could permit remote
attackers unintended access to internals of the registered object or
its module or possibly other modules.  The flaw only affects Python
XML-RPC servers that use the register_instance() method to register an
object without a _dispatch() method.  Servers using only
register_function() are not affected.

For the stable distribution (woody) this problem has been fixed in
version 2.2.1-4.7.  No other version of Python in woody is affected.

For the testing (sarge) and unstable (sid) distributions the following
matrix explains which version will contain the correction in which
version:

testing                   unstable
Python 2.2     2.2.3-14                  2.2.3-14
Python 2.3     2.3.4-20               2.3.4+2.3.5c1-2
Python 2.4      2.4-5                     2.4-5

We recommend that you upgrade your Python packages.";
tag_summary = "The remote host is missing an update to python2.2
announced via advisory DSA 666-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20666-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303884");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(12437);
 script_cve_id("CVE-2005-0089");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 666-1 (python2.2)");



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
if ((res = isdpkgvuln(pkg:"idle-python2.2", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-doc", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-elisp", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-examples", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-dev", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-gdbm", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-mpz", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-tk", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2-xmlbase", ver:"2.2.1-4.7", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
