# OpenVAS Vulnerability Test
# $Id: deb_1912_2.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1912-2 (advi)
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
tag_insight = "Due to the fact that advi, an active DVI previewer and presenter,
statically links against camlimages it was necessary to rebuilt it in
order to incorporate the latest security fixes for camlimages, which
could lead to integer overflows via specially crafted TIFF files
(CVE-2009-3296) or GIFF and JPEG images (CVE-2009-2660).


For the stable distribution (lenny), these problems have been fixed in
version 1.6.0-13+lenny2.

Due to a bug in the archive system, the fix for the oldstable
distribution (etch) cannot be released at the same time. These problems
will be fixed in version 1.6.0-12+etch2, once it is available.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 1.6.0-14+b1.


We recommend that you upgrade your advi package.";
tag_summary = "The remote host is missing an update to advi
announced via advisory DSA 1912-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201912-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310881");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-3296", "CVE-2009-2660");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1912-2 (advi)");



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
if ((res = isdpkgvuln(pkg:"advi-examples", ver:"1.6.0-13+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"advi", ver:"1.6.0-13+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
