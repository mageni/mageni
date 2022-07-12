# OpenVAS Vulnerability Test
# $Id: deb_1396_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1396-1
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
tag_insight = "Several remote vulnerabilities have been discovered in the Iceweasel web
browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1095

Michal Zalewski discovered that the unload event handler had access to
the address of the next page to be loaded, which could allow information
disclosure or spoofing.

CVE-2007-2292

Stefano Di Paola discovered that insufficient validation of user names
used in Digest authentication on a web site allows HTTP response splitting
attacks.

CVE-2007-3511

It was discovered that insecure focus handling of the file upload
control can lead to information disclosure. This is a variant of
CVE-2006-2894.

CVE-2007-5334

Eli Friedman discovered that web pages written in Xul markup can hide the
titlebar of windows, which can lead to spoofing attacks.

CVE-2007-5337

Georgi Guninski discovered the insecure handling of smb:// and sftp:// URI
schemes may lead to information disclosure. This vulnerability is only
exploitable if Gnome-VFS support is present on the system.

CVE-2007-5338

moz_bug_r_a4 discovered that the protection scheme offered by XPCNativeWrappers
could be bypassed, which might allow privilege escalation.

CVE-2007-5339

L. David Baron, Boris Zbarsky, Georgi Guninski, Paul Nickerson, Olli Pettay,
Jesse Ruderman, Vladimir Sukhoy, Daniel Veditz, and Martijn Wargers discovered
crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-5340

Igor Bukanov, Eli Friedman, and Jesse Ruderman discovered crashes in the
Javascript engine, which might allow the execution of arbitrary code.

The Mozilla products in the oldstable distribution (sarge) are no longer
supported with with security updates.

For the stable distribution (etch) these problems have been fixed in version
2.0.0.6+2.0.0.8-0etch1. Builds for arm and sparc will be provided later.

For the unstable distribution (sid) these problems have been fixed in version
2.0.0.8-1.

We recommend that you upgrade your iceweasel packages.";
tag_summary = "The remote host is missing an update to icedove
announced via advisory DSA 1396-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201396-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300952");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340", "CVE-2006-2894");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1396-1 (icedove)");



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
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.6+2.0.0.8-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.6-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.6-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.6-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
