# OpenVAS Vulnerability Test
# $Id: deb_1669_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1669-1 (xulrunner)
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
tag_insight = "Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. For details on the issues
addressed with this update, please visit the referenced security
advisories.

For the stable distribution (etch), these problems have been fixed in
version 1.8.0.15~pre080614h-0etch1. Packages for mips will be provided
later.

For the upcoming stable distribution (lenny) and the unstable
distribution (sid), these problems have been fixed in version 1.9.0.4-1.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 1669-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201669-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302888");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
 script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-0017", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1669-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libsmjs-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmjs1", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul-common", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-tools", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-gnome-support", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
