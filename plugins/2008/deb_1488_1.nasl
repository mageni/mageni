# OpenVAS Vulnerability Test
# $Id: deb_1488_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1488-1 (phpbb2)
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
tag_insight = "Several remote vulnerabilities have been discovered in phpBB, a web
based bulletin board.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-0471

Private messaging allowed cross site request forgery, making
it possible to delete all private messages of a user by sending
them to a crafted web page.

CVE-2006-6841 / CVE-2006-6508

Cross site request forgery enabled an attacker to perform various
actions on behalf of a logged in user. (Applies to sarge only)

CVE-2006-6840

A negative start parameter could allow an attacker to create
invalid output. (Applies to sarge only)

CVE-2006-6839

Redirection targets were not fully checked, leaving room for
unauthorised external redirections via a phpBB forum.
(Applies to sarge only)

CVE-2006-4758

An authenticated forum administrator may upload files of any
type by using specially crafted filenames. (Applies to sarge only)


For the stable distribution (etch), these problems have been fixed
in version 2.0.21-7.

For the old stable distribution (sarge), these problems have been
fixed in version 2.0.13+1-6sarge4.

For the unstable distribution (sid) these problems have been fixed
in version 2.0.22-3.

We recommend that you upgrade your phpbb2 package.";
tag_summary = "The remote host is missing an update to phpbb2
announced via advisory DSA 1488-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201488-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300645");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
 script_cve_id("CVE-2006-4758", "CVE-2006-6839", "CVE-2006-6840", "CVE-2006-6508", "CVE-2006-6841", "CVE-2008-0471");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1488-1 (phpbb2)");



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
if ((res = isdpkgvuln(pkg:"phpbb2-conf-mysql", ver:"2.0.13-6sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2", ver:"2.0.13-6sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2-languages", ver:"2.0.13-6sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2-languages", ver:"2.0.21-7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2", ver:"2.0.21-7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpbb2-conf-mysql", ver:"2.0.21-7", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
