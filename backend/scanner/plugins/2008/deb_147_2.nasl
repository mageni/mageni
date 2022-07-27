# OpenVAS Vulnerability Test
# $Id: deb_147_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 147-2
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
tag_insight = "Quoting DSA 147-1:

A cross-site scripting vulnerability was discovered in mailman, a
software to manage electronic mailing lists.  When a properly
crafted URL is accessed with Internet Explorer (other browsers
don't seem to be affected), the resulting webpage is rendered
similar to the real one, but the javascript component is executed
as well, which could be used by an attacker to get access to
sensitive information.  The new version for Debian 2.2 also
includes backports of security related patches from mailman 2.0.11.

This has been fixed in DSA 147-1 already, however, contrary to popular
belief, it turned out that the Python packaging does not upgrade
Python 1.5 users to 2.1 when upgrading from potato to woody.  It also
turned out that the mailman security update unwittingly introduced a
dependency to Python 2.1, both in the security update and upstream,
which left the package unusable on some systems.

This problem has been fixed in version 2.0.11-1woody4 for the current
stable distribution (woody).  Others are not affected.

We recommend that you upgrade your mailman package.";
tag_summary = "The remote host is missing an update to mailman
announced via advisory DSA 147-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20147-2";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304307");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0388");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 147-2 (mailman)");



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
if ((res = isdpkgvuln(pkg:"mailman", ver:"2.0.11-1woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
