# OpenVAS Vulnerability Test
# $Id: deb_2092_1.nasl 8440 2018-01-17 07:58:46Z teissa $
# Description: Auto-generated from advisory DSA 2092-1 (lxr-cvs)
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
tag_insight = "Dan Rosenberg discovered that in lxr-cvs, a code-indexing tool with a
web frontend, not enough sanitation of user input is performed; an
attacker can take advantage of this and pass script code in order to
perform cross-site scripting attacks.


For the stable distribution (lenny), this problem has been fixed in
version 0.9.5+cvs20071020-1+lenny1.

For the testing distribution (sid), this problem has been fixed in
version 0.9.5+cvs20071020-1.1.

We recommend that you upgrade your lxr-cvs packages.";
tag_summary = "The remote host is missing an update to lxr-cvs
announced via advisory DSA 2092-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202092-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314336");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2010-1448", "CVE-2009-4497", "CVE-2010-1625");
 script_name("Debian Security Advisory DSA 2092-1 (lxr-cvs)");



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
if ((res = isdpkgvuln(pkg:"lxr-cvs", ver:"0.9.5+cvs20071020-1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
