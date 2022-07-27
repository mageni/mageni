# OpenVAS Vulnerability Test
# $Id: deb_911_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 911-1
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
tag_insight = "Several vulnerabilities have been found in gtk+2.0, the Gtk+ GdkPixBuf
XPM image rendering library.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2005-2975

Ludwig Nussel discovered an infinite loop when processing XPM
images that allows an attacker to cause a denial of service via a
specially crafted XPM file.

CVE-2005-2976

Ludwig Nussel discovered an integer overflow in the way XPM images
are processed that could lead to the execution of arbitrary code
or crash the application via a specially crafted XPM file.

CVE-2005-3186

infamous41md discovered an integer in the XPM processing routine
that can be used to execute arbitrary code via a traditional heap
overflow.

The following matrix explains which versions fix these problems:

old stable (woody)    stable (sarge)   unstable (sid)
gdk-pixbuf     0.17.0-2woody3        0.22.0-8.1       0.22.0-11
gtk+2.0         2.0.2-5woody3         2.6.4-3.1        2.6.10-2

We recommend that you upgrade your gtk+2.0 packages.";
tag_summary = "The remote host is missing an update to gtk+2.0
announced via advisory DSA 911-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20911-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300281");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 script_bugtraq_id(15428);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 911-1 (gtk+2.0)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libgtk2.0-doc", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gtk2.0-examples", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk-common", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-0", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-common", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-dbg", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-dev", ver:"2.0.2-5woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-common", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-doc", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gtk2-engines-pixbuf", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gtk2.0-examples", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-0", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-0-dbg", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-bin", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgtk2.0-dev", ver:"2.6.4-3.1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
