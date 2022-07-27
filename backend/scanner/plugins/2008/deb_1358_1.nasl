# OpenVAS Vulnerability Test
# $Id: deb_1358_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1358-1
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
tag_insight = "Several remote vulnerabilities have been discovered in Asterisk, a free
software PBX and telephony toolkit. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2007-1306

Mu Security discovered that a NULL pointer deference in the SIP
implementation could lead to denial of service.

CVE-2007-1561

Inria Lorraine discovered that a programming error in the SIP
implementation could lead to denial of service.

CVE-2007-2294

It was discovered that a NULL pointer deference in the manager
interface could lead to denial of service.

CVE-2007-2297

It was discovered that a programming error in the SIP implementation
could lead to denial of service.

CVE-2007-2488

Tim Panton and Birgit Arkestein discovered that a programming error
in the IAX2 implementation could lead to information disclosure.

CVE-2007-3762

Russell Bryant discovered that a buffer overflow in the IAX
implementation could lead to the execution of arbitrary code.

CVE-2007-3763

Chris Clark and Zane Lackey discovered that several NULL pointer
deferences in the IAX2 implementation could lead to denial of
service.

CVE-2007-3764

Will Drewry discovered that a programming error in the Skinny
implementation could lead to denial of service.

For the oldstable distribution (sarge) these problems have been fixed in
version 1.0.7.dfsg.1-2sarge5.

For the stable distribution (etch) these problems have been fixed
in version 1:1.2.13~dfsg-2etch1.

For the unstable distribution (sid) these problems have been fixed in
version 1:1.4.11~dfsg-1.

We recommend that you upgrade your Asterisk packages.";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory DSA 1358-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201358-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304093");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1306", "CVE-2007-1561", "CVE-2007-2294", "CVE-2007-2297", "CVE-2007-2488", "CVE-2007-3762", "CVE-2007-3763", "CVE-2007-3764");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1358-1 (asterisk)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-web-vmail", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-gtk-console", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1.0.7.dfsg.1-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-web-vmail", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-bristuff", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-classic", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1.2.13~dfsg-2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
