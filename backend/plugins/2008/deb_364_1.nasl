# OpenVAS Vulnerability Test
# $Id: deb_364_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 364-1
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
tag_insight = "man-db provides the standard man(1) command on Debian systems.  During
configuration of this package, the administrator is asked whether
man(1) should run setuid to a dedicated user ('man') in order to
provide a shared cache of preformatted manual pages.  The default is
for man(1) NOT to be setuid, and in this configuration no known
vulnerability exists.  However, if the user explicitly requests setuid
operation, a local attacker could exploit either of the following bugs to
execute arbitrary code as the 'man' user.

Again, these vulnerabilities do not affect the default configuration,
where man is not setuid.

- - CVE-2003-0620: Multiple buffer overflows in man-db 2.4.1 and
earlier, when installed setuid, allow local users to gain privileges
via (1) MANDATORY_MANPATH, MANPATH_MAP, and MANDB_MAP arguments to
add_to_dirlist in manp.c, (2) a long pathname to ult_src in
ult_src.c, (3) a long .so argument to test_for_include in ult_src.c,
(4) a long MANPATH environment variable, or (5) a long PATH
environment variable.

- - CVE-2003-0645: Certain DEFINE directives in ~/.manpath, which
contained commands to be executed, would be honored even when
running setuid, allowing any user to execute commands as the
'man' user.

For the current stable distribution (woody), these problems have been
fixed in version 2.3.20-18.woody.2.

For the unstable distribution (sid), these problems have been fixed in
version 2.4.1-12.

We recommend that you update your man-db package.";
tag_summary = "The remote host is missing an update to man-db
announced via advisory DSA 364-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20364-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300953");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0620", "CVE-2003-0645");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 364-1 (man-db)");



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
if ((res = isdpkgvuln(pkg:"man-db", ver:"2.3.20-18.woody.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
