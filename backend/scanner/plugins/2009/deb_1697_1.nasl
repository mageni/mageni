# OpenVAS Vulnerability Test
# $Id: deb_1697_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1697-1 (iceape)
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
tag_insight = "Several remote vulnerabilities have been discovered in Iceape an
unbranded version of the Seamonkey internet suite. The Common
Vulnerabilities and Exposures project identifies the following problems:

For details, please visit the referenced security advisories.

For the stable distribution (etch) these problems have been fixed in
version 1.0.13~pre080614i-0etch1.

For the upcoming stable distribution (lenny) distribution these problems
will be fixed soon.

For the unstable (sid) distribution these problems have been fixed in
version 1.1.14-1.

We recommend that you upgrade your iceape packages.";
tag_summary = "The remote host is missing an update to iceape
announced via advisory DSA 1697-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201697-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306532");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2008-0016", "CVE-2008-0304", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811", "CVE-2008-2933", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069", "CVE-2008-4070", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-0017", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5024", "CVE-2008-4582");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1697-1 (iceape)");



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
if ((res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-calendar", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-psm", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dev", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-browser", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-dev", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"1.8+1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dbg", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-mailnews", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-gnome-support", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dom-inspector", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-browser", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-calendar", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
