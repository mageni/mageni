# OpenVAS Vulnerability Test
# $Id: deb_2022_1.nasl 8528 2018-01-25 07:57:36Z teissa $
# Description: Auto-generated from advisory DSA 2022-1 (mediawiki)
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
tag_insight = "Several vulnerabilities have been discovered in mediawiki, a web-based wiki
engine.  The following issues have been identified:

Insufficient input sanitization in the CSS validation code allows editors
to display external images in wiki pages.  This can be a privacy concern
on public wikis as it allows attackers to gather IP addresses and other
information by linking these images to a web server under their control.

Insufficient permission checks have been found in thump.php which can lead
to disclosure of image files that are restricted to certain users
(e.g. with img_auth.php).


For the stable distribution (lenny), this problem has been fixed in
version 1.12.0-2lenny4.

For the testing distribution (squeeze), this problem has been fixed in
version 1:1.15.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.15.2-1.";
tag_summary = "The remote host is missing an update to mediawiki
announced via advisory DSA 2022-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202022-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313140");
 script_cve_id("CVE-2010-1189","CVE-2010-1190");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-30 18:37:46 +0200 (Tue, 30 Mar 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 2022-1 (mediawiki)");



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
if ((res = isdpkgvuln(pkg:"mediawiki", ver:"1.12.0-2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mediawiki-math", ver:"1.12.0-2lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
