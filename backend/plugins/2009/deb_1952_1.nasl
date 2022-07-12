# OpenVAS Vulnerability Test
# $Id: deb_1952_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1952-1 (asterisk)
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
tag_insight = "Several vulnerabilities have been discovered in asterisk, an Open Source
PBX and telephony toolkit. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-0041

It is possible to determine valid login names via probing, due to the
IAX2 response from asterisk (AST-2009-001).

CVE-2008-3903

It is possible to determine a valid SIP username, when Digest
authentication and authalwaysreject are enabled (AST-2009-003).

CVE-2009-3727

It is possible to determine a valid SIP username via multiple crafted
REGISTER messages (AST-2009-008).

CVE-2008-7220 CVE-2007-2383

It was discovered that asterisk contains an obsolete copy of the
Prototype JavaScript framework, which is vulnerable to several security
issues. This copy is unused and now removed from asterisk
(AST-2009-009).

CVE-2009-4055

It was discovered that it is possible to perform a denial of service
attack via  RTP comfort noise payload with a long data length
(AST-2009-010).


For the stable distribution (lenny), these problems have been fixed in
version 1:1.4.21.2~dfsg-3+lenny1.

The security support for asterisk in the oldstable distribution (etch)
has been discontinued before the end of the regular Etch security
maintenance life cycle. You are strongly encouraged to upgrade to
stable.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 1:1.6.2.0~rc7-1.


We recommend that you upgrade your asterisk packages.";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory DSA 1952-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201952-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309170");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2009-0041", "CVE-2008-3903", "CVE-2009-3727", "CVE-2008-7220", "CVE-2009-4055", "CVE-2007-2383");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1952-1 (asterisk)");



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
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1.4.21.2~dfsg-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
