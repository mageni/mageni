# OpenVAS Vulnerability Test
# $Id: deb_946_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 946-1
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.3.

For the unstable distribution (sid) this problem has been fixed in
version 1.6.8p12-1.

We recommend that you upgrade your sudo package.  For unstable

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20946-1";
tag_summary = "The remote host is missing an update to sudo
announced via advisory DSA 946-1.

It has been discovered that sudo, a privileged program, that provides
limited super user privileges to specific users, passes several
environment variables to the program that runs with elevated
privileges.  In the case of include paths (e.g. for Perl, Python, Ruby
or other scripting languages) this can cause arbitrary code to be
executed as privileged user if the attacker points to a manipulated
version of a system library.

This update alters the former behaviour of sudo and limits the number
of supported environment variables to LC_*, LANG, LANGUAGE and TERM.
Additional variables are only passed through when set as env_check in
/etc/sudoers, which might be required for some scripts to continue to
work.

For the old stable distribution (woody) this problem has been fixed in
version 1.6.6-1.5.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303848");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-4158", "CVE-2006-0151");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 946-1 (sudo)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"sudo", ver:"1.6.6-1.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sudo", ver:"1.6.8p7-1.3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
