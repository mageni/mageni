# OpenVAS Vulnerability Test
# $Id: deb_2045_1.nasl 8495 2018-01-23 07:57:49Z teissa $
# Description: Auto-generated from advisory DSA 2045-1 (libtheora)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Bob Clary, Dan Kaminsky and David Keeler discovered that in libtheora, a
video library part of the Ogg project, several flaws allow allow
context-dependent attackers via a large and specially crafted media
file, to cause a denial of service (crash of the player using this
library), and possibly arbitrary code execution.

For the stable distribution (lenny), this problem has been fixed in
version 1.0~beta3-1+lenny1.

For the testing distribution (squeeze), this problem has been fixed in
version 1.1.0-1.

For the testing distribution (sid), this problem has been fixed in
version 1.1.0-1.

We recommend that you upgrade your libtheora packages.";
tag_summary = "The remote host is missing an update to libtheora
announced via advisory DSA 2045-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202045-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313278");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-3389");
 script_name("Debian Security Advisory DSA 2045-1 (libtheora)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libtheora0", ver:"1.0~beta3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtheora-dev", ver:"1.0~beta3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtheora-bin", ver:"1.0~beta3-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
