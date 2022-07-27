# OpenVAS Vulnerability Test
# $Id: deb_1667_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1667-1 (python2.4)
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
tag_insight = "Several vulnerabilities have been discovered in the interpreter for the
Python language. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-2315

David Remahl discovered several integer overflows in the
stringobject, unicodeobject,  bufferobject, longobject,
tupleobject, stropmodule, gcmodule, and mmapmodule modules.

CVE-2008-3142

Justin Ferguson discovered that incorrect memory allocation in
the unicode_resize() function can lead to buffer overflows.

CVE-2008-3143

Several integer overflows were discovered in various Python core
modules.

CVE-2008-3144

Several integer oberflows were discovered in the PyOS_vsnprintf()
function.

For the stable distribution (etch), these problems have been fixed in
version 2.4.4-3+etch2.

For the unstable distribution (sid) and the upcoming stable
distribution (lenny), these problems have been fixed in
version 2.4.5-5.

We recommend that you upgrade your python2.4 packages.";
tag_summary = "The remote host is missing an update to python2.4
announced via advisory DSA 1667-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201667-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303171");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
 script_cve_id("CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1667-1 (python2.4)");



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
if ((res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.4-3+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.4-3+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.4-3+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.4-3+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4", ver:"2.4.4-3+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.4-3+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
