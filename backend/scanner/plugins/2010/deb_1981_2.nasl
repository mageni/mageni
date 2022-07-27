# OpenVAS Vulnerability Test
# $Id: deb_1981_2.nasl 8457 2018-01-18 07:58:32Z teissa $
# Description: Auto-generated from advisory DSA 1981-2 (maildrop)
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
tag_insight = "The latest DSA for maildrop introduced two regressions. The maildrop
program stopped working when invoked as a non-root user, such as with
postfix. Also, the lenny version dropped a dependency on the
courier-authlib package.


For the stable distribution (lenny), this problem has been fixed in
version 2.0.4-3+lenny3.

For the oldstable distribution (etch), this problem has been fixed in
version 2.0.2-11+etch2.

For the testing distribution (squeeze) this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.2.0-3.1.

For reference, the original advisory text is below.

Christoph Anton Mitterer discovered that maildrop, a mail delivery agent
with filtering abilities, is prone to a privilege escalation issue that
grants a user root group privileges.

We recommend that you upgrade your maildrop packages.";
tag_summary = "The remote host is missing an update to maildrop
announced via advisory DSA 1981-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201981-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313545");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-01 18:25:19 +0100 (Mon, 01 Feb 2010)");
 script_cve_id("CVE-2010-0301");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1981-2 (maildrop)");



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
if ((res = isdpkgvuln(pkg:"maildrop", ver:"2.0.2-11+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"maildrop", ver:"2.0.4-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
