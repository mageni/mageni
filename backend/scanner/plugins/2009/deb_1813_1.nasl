# OpenVAS Vulnerability Test
# $Id: deb_1813_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1813-1 (evolution-data-server)
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
tag_insight = "Several vulnerabilities have been found in evolution-data-server, the
database backend server for the evolution groupware suite. The Common
Vulnerabilities and Exposures project identifies the following problems:


CVE-2009-0587

It was discovered that evolution-data-server is prone to integer
overflows triggered by large base64 strings.

CVE-2009-0547

Joachim Breitner discovered that S/MIME signatures are not verified
properly, which can lead to spoofing attacks.

CVE-2009-0582

It was discovered that NTLM authentication challenge packets are not
validated properly when using the NTLM authentication method, which
could lead to an information disclosure or a denial of service.


For the oldstable distribution (etch), these problems have been fixed in
version 1.6.3-5etch2.

For the stable distribution (lenny), these problems have been fixed in
version 2.22.3-1.1+lenny1.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 2.26.1.1-1.


We recommend that you upgrade your evolution-data-server packages.";
tag_summary = "The remote host is missing an update to evolution-data-server
announced via advisory DSA 1813-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201813-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309477");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
 script_cve_id("CVE-2009-0587", "CVE-2009-0547", "CVE-2009-0582");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1813-1 (evolution-data-server)");



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
if ((res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-6", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-5", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-8", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-1", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-6", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-5", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-7", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-10", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-3", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-9", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdata1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-9", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdata-google1.2-1", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdata-google1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-6", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-7", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgdata1.2-1", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-11", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-13", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-8", ver:"2.22.3-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
