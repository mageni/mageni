# OpenVAS Vulnerability Test
# $Id: deb_1890_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1890-1 (wxwindows2.4 wxwidgets2.6 wxwidgets2.8)
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
tag_insight = "Tielei Wang has discovered an integer overflow in wxWidgets, the wxWidgets
Cross-platform C++ GUI toolkit, which allows the execution of arbitrary
code via a crafted JPEG file.

For the oldstable distribution (etch), this problem has been fixed in version
2.4.5.1.1+etch1 for wxwindows2.4 and version 2.6.3.2.1.5+etch1 for
wxwidgets2.6.

For the stable distribution (lenny), this problem has been fixed in version
2.6.3.2.2-3+lenny1 for wxwidgets2.6 and version 2.8.7.1-1.1+lenny1 for
wxwidgets2.8.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.8.7.1-2 for wxwidgets2.8 and will be fixed soon for
wxwidgets2.6.


We recommend that you upgrade your wxwidgets packages.";
tag_summary = "The remote host is missing an update to wxwindows2.4 wxwidgets2.6 wxwidgets2.8
announced via advisory DSA 1890-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201890-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311716");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-21 23:13:00 +0200 (Mon, 21 Sep 2009)");
 script_cve_id("CVE-2009-2369");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1890-1 (wxwindows2.4 wxwidgets2.6 wxwidgets2.8)");



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
if ((res = isdpkgvuln(pkg:"wx2.6-i18n", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxtools", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-examples", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-doc", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.4-i18n", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxversion", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.4-doc", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.4-examples", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxgtk2.4", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.4-dev", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.4-headers", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.6-dbg", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx-common", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.6-dev", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.4-dev", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.4-dbg", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.4-dbg", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.4-1", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxgtk2.6", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.6-0", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.4-1", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.4-contrib-dev", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.6-0", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.4-1-contrib", ver:"2.4.5.1.1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.6-dev", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-headers", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.6-dbg", ver:"2.6.3.2.1.5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-examples", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.8-i18n", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxtools", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.8-doc", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxversion", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-doc", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-i18n", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.8-examples", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxgtk2.8-dbg", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx-common", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.6-headers", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.8-0", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxgtk2.8", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.8-dev", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.6-dev", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wx2.8-headers", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.6-dbg", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.8-dev", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.8-0", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxgtk2.6", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.6-0", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxgtk2.8-dbg", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.6-dev", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-wxgtk2.6-dbg", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.8-dbg", ver:"2.8.7.1-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.6-dbg", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwxbase2.6-0", ver:"2.6.3.2.2-3+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
