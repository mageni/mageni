# OpenVAS Vulnerability Test
# $Id: deb_307_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 307-1
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
tag_insight = "Timo Sirainen discovered several problems in BitchX, a popular client
for Internet Relay Chat (IRC).  A malicious server could craft special
reply strings, triggering the client to write beyond buffer boundaries
or allocate a negative amount of memory.  This could lead to a denial
of service if the client only crashes, but may also lead to executing
of arbitrary code under the user id of the chatting user.

For the stable distribution (woody) these problems have been fixed in
version 1.0-0c19-1.1.

For the old stable distribution (potato) these problems have been
fixed in version 1.0-0c16-2.1.

For the unstable distribution (sid) these problems have been fixed in
version 1.0-0c19-8.

We recommend that you upgrade your BitchX package.";
tag_summary = "The remote host is missing an update to ircii-pana
announced via advisory DSA 307-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20307-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303299");
 script_cve_id("CVE-2003-0360","CVE-2003-0361","CVE-2003-0362");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_name("Debian Security Advisory DSA 307-1 (ircii-pana)");



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
if ((res = isdpkgvuln(pkg:"bitchx", ver:"1.0-0c16-2.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bitchx-gtk", ver:"1.0-0c16-2.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bitchx", ver:"1.0-0c19-1.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bitchx-dev", ver:"1.0-0c19-1.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bitchx-gtk", ver:"1.0-0c19-1.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bitchx-ssl", ver:"1.0-0c19-1.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
