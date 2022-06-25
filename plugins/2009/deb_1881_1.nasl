# OpenVAS Vulnerability Test
# $Id: deb_1881_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1881-1 (cyrus-imapd-2.2)
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
tag_insight = "It was discovered that the SIEVE component of cyrus-imapd, a highly scalable
enterprise mail system, is vulnerable to a buffer overflow when processing
SIEVE scripts.  Due to incorrect use of the sizeof() operator an attacker is
able to pass a negative length to snprintf() calls resulting in large positive
values due to integer conversion.  This causes a buffer overflow which can be
used to elevate privileges to the cyrus system user.  An attacker who is able
to install SIEVE scripts executed by the server is therefore able to read and
modify arbitrary email messages on the system.


For the oldstable distribution (etch), this problem has been fixed in
version 2.2.13-10+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 2.2.13-14+lenny1.

For the testing (squeeze) and unstable (sid) distribution, this problem
will be fixed soon.


We recommend that you upgrade your cyrus-imapd-2.2 packages.";
tag_summary = "The remote host is missing an update to cyrus-imapd-2.2
announced via advisory DSA 1881-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201881-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309195");
 script_cve_id("CVE-2009-2632");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1881-1 (cyrus-imapd-2.2)");



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
if ((res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-10+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-admin-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-doc-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-nntpd-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-dev-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcyrus-imap-perl22", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-pop3d-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-common-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-imapd-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-murder-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-clients-2.2", ver:"2.2.13-14+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
