# OpenVAS Vulnerability Test
# $Id: deb_1730_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1730-1 (proftpd-dfsg)
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
tag_insight = "The security update for proftpd-dfsg in DSA-1727-1 caused a regression
with the postgresql backend. This update corrects the flaw. Also it was
discovered that the oldstable distribution (etch) is not affected by the
security issues. For reference the original advisory follows.


Two SQL injection vulnerabilities have been found in proftpd, a
virtual-hosting FTP daemon. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-0542

Shino discovered that proftpd is prone to an SQL injection vulnerability
via the use of certain characters in the username.


CVE-2009-0543

TJ Saunders discovered that proftpd is prone to an SQL injection
vulnerability due to insufficient escaping mechanisms, when multybite
character encodings are used.


For the stable distribution (lenny), these problems have been fixed in
version 1.3.1-17lenny2.

The oldstable distribution (etch) is not affected by these problems.

For the unstable distribution (sid), these problems have been fixed in
version 1.3.2-1.

For the testing distribution (squeeze), these problems will be fixed
soon.";
tag_summary = "The remote host is missing an update to proftpd-dfsg
announced via advisory DSA 1730-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201730-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310414");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2009-0542", "CVE-2009-0543");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1730-1 (proftpd-dfsg)");



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
if ((res = isdpkgvuln(pkg:"proftpd", ver:"1.3.1-17lenny2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.1-17lenny2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.1-17lenny2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.1-17lenny2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.1-17lenny2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.1-17lenny2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
