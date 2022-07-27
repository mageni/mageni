# OpenVAS Vulnerability Test
# $Id: deb_1689_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1689-1 (proftpd-dfsg)
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
tag_insight = "Maksymilian Arciemowicz of securityreason.com reported that ProFTPD is
vulnerable to cross-site request forgery (CSRF) attacks and executes
arbitrary FTP commands via a long ftp:// URI that leverages an
existing session from the FTP client implementation in a web browser.

For the stable distribution (etch) this problem has been fixed in
version 1.3.0-19etch2 and in version 1.3.1-15~bpo40+1 for backports.

For the testing (lenny) and unstable (sid) distributions this problem
has been fixed in version 1.3.1-15.

We recommend that you upgrade your proftpd-dfsg package.";
tag_summary = "The remote host is missing an update to proftpd-dfsg
announced via advisory DSA 1689-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201689-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301229");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-12-29 22:42:24 +0100 (Mon, 29 Dec 2008)");
 script_cve_id("CVE-2008-4242");
 script_bugtraq_id(31289);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1689-1 (proftpd-dfsg)");



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
if ((res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.0-19etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-ldap", ver:"1.3.0-19etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mysql", ver:"1.3.0-19etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-pgsql", ver:"1.3.0-19etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd", ver:"1.3.0-19etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
