# OpenVAS Vulnerability Test
# $Id: deb_1555_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1555-1 (iceweasel)
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
tag_insight = "It was discovered that crashes in the Javascript engine of Iceweasel,
an unbranded version of the Firefox browser could potentially lead to
the execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in
version 2.0.0.14-0etch1

For the unstable distribution (sid), this problem has been fixed in
version 2.0.0.14-1.

We recommend that you upgrade your iceweasel package.";
tag_summary = "The remote host is missing an update to iceweasel
announced via advisory DSA 1555-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201555-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302099");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-30 19:28:13 +0200 (Wed, 30 Apr 2008)");
 script_cve_id("CVE-2008-1380");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1555-1 (iceweasel)");



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
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.14-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
