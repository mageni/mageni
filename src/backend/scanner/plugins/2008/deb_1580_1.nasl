# OpenVAS Vulnerability Test
# $Id: deb_1580_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1580-1 (phpgedview)
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
tag_insight = "It was discovered that phpGedView, an application to provide online access
to genealogical data, allowed remote attackers to gain administrator
privileges due to a programming error.

Note: this problem was a fundamental design flaw in the interface (API) to
connect phpGedView with external programs like content management systems.
Resolving this problem was only possible by completely reworking the API,
which is not considered appropriate for a security update. Since these are
peripheral functions probably not used by the large majority of package
users, it was decided to remove these interfaces. If you require that
interface nonetheless, you are advised to use a version of phpGedView
backported from Debian Lenny, which has a completely redesigned API.

For the stable distribution (etch), this problem has been fixed in
version 4.0.2.dfsg-4.

For the unstable distribution (sid), this problem has been fixed in
version 4.1.e+4.1.5-1.

We recommend that you upgrade your phpgedview package.";
tag_summary = "The remote host is missing an update to phpgedview
announced via advisory DSA 1580-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201580-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301859");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-05-27 15:41:50 +0200 (Tue, 27 May 2008)");
 script_cve_id("CVE-2008-2064");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1580-1 (phpgedview)");



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
if ((res = isdpkgvuln(pkg:"phpgedview", ver:"4.0.2.dfsg-4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgedview-languages", ver:"4.0.2.dfsg-4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgedview-places", ver:"4.0.2.dfsg-4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgedview-themes", ver:"4.0.2.dfsg-4", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
