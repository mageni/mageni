# OpenVAS Vulnerability Test
# $Id: deb_1690_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1690-1 (avahi)
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
tag_insight = "Two denial of service conditions were discovered in avahi, a Multicast
DNS implementation.

Huge Dias discovered that the avahi daemon aborts with an assert error
if it encounters a UDP packet with source port 0 (CVE-2008-5081).

It was discovered that the avahi daemon aborts with an assert error if
it receives an empty TXT record over D-Bus (CVE-2007-3372).

For the stable distribution (etch), these problems have been fixed in
version 0.6.16-3etch2.

For the unstable distribution (sid), these problems have been fixed in
version 0.6.23-3.

We recommend that you upgrade your avahi packages.";
tag_summary = "The remote host is missing an update to avahi
announced via advisory DSA 1690-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201690-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301177");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-12-29 22:42:24 +0100 (Mon, 29 Dec 2008)");
 script_cve_id("CVE-2007-3372", "CVE-2008-5081");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1690-1 (avahi)");



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
if ((res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-avahi", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-core4", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-howl0", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt3-1", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt4-1", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-howl-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-autoipd", ver:"0.6.16-3etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
