# OpenVAS Vulnerability Test
# $Id: deb_1305_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1305-1
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
tag_insight = "Several remote vulnerabilities have been discovered in the Icedove mail client,
an unbranded version of the Thunderbird client. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2007-1558

Gatan Leurent discovered a cryptographical weakness in APOP
authentication, which reduces the required efforts for an MITM attack
to intercept a password. The update enforces stricter validation, which
prevents this attack.

CVE-2007-2867

Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse Ruderman, Martijn
Wargers and Olli Pettay discovered crashes in the layout engine, which
might allow the execution of arbitrary code.

CVE-2007-2868

Brendan Eich, Igor Bukanov, Jesse Ruderman, moz_bug_r_a4 and Wladimir Palant
discovered crashes in the Javascript engine, which might allow the execution of
arbitrary code. Generally, enabling Javascript in Icedove is not recommended.

Fixes for the oldstable distribution (sarge) are not available. While there
will be another round of security updates for Mozilla products, Debian doesn't
have the ressources to backport further security fixes to the old Mozilla
products. You're strongly encouraged to upgrade to stable as soon as possible.

For the stable distribution (etch) these problems have been fixed in version
1.5.0.12.dfsg1-0etch1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your icedove packages.";
tag_summary = "The remote host is missing an update to icedove
announced via advisory DSA 1305-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201305-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303603");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1305-1 (icedove)");



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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-inspector", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-typeaheadfind", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-inspector", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-typeaheadfind", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
