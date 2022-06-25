# OpenVAS Vulnerability Test
# $Id: deb_2086_1.nasl 8510 2018-01-24 07:57:42Z teissa $
# Description: Auto-generated from advisory DSA 2086-1 (avahi)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in the Avahi mDNS/DNS-SD
daemon. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2009-0758

Rob Leslie discovered a denial of service vulnerability in the
code used to reflect unicast mDNS traffic.

CVE-2010-2244

Ludwig Nussel discovered a denial of service vulnerability in
the processing of malformed DNS packets.

For the stable distribution (lenny), this problem has been fixed in
version 0.6.23-3lenny2.

For the unstable distribution (sid), these problems have been fixed in
version 0.6.26-1.

We recommend that you upgrade your Avahi packages.";
tag_summary = "The remote host is missing an update to avahi
announced via advisory DSA 2086-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202086-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312757");
 script_version("$Revision: 8510 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2009-0758", "CVE-2010-2244");
 script_name("Debian Security Advisory DSA 2086-1 (avahi)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"python-avahi", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-gobject0", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-howl-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-autoipd", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-ui-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt4-1", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-core5", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-ui0", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-ui-utils", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-dbg", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-howl0", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt3-1", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-gobject-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.6.23-3lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
