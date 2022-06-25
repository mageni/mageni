# OpenVAS Vulnerability Test
# $Id: deb_1878_2.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1878-2 (devscripts)
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
tag_insight = "This update corrects regressions introduced by the devscripts security
update, DSA-1878-1.  The original announcement was:

Raphael Geissert discovered that uscan, a program to check for
availability of new source code versions which is part of the
devscripts package, runs Perl code downloaded from potentially
untrusted sources to implement its URL and version mangling
functionality.  This update addresses this issue by reimplementing the
relevant Perl operators without relying on the Perl interpreter,
trying to preserve backwards compatibility as much as possible.

For the old stable distribution (etch), this problem has been fixed in
version 2.9.26etch5.

For the stable distribution (lenny), this problem has been fixed in
version 2.10.35lenny7.

For the unstable distribution (sid), this problem will be fixed in
version 2.10.55.

We recommend that you upgrade your devscripts package.";
tag_summary = "The remote host is missing an update to devscripts
announced via advisory DSA 1878-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201878-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305376");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2009-2946");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1878-2 (devscripts)");



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
if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.9.26etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.35lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
