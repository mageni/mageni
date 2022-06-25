# OpenVAS Vulnerability Test
# $Id: deb_1007_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1007-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-6.

For the unstable distribution (sid) these problems have been fixed in
version 4.5.8-1.

We recommend that you upgrade your drupal package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201007-1";
tag_summary = "The remote host is missing an update to drupal
announced via advisory DSA 1007-1.


The Drupal Security Team discovered several vulnerabilities in Drupal,
a fully-featured content management and discussion engine.  The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2006-1225

Due to missing input sanitising a remote attacker could inject
headers of outgoing e-mail messages and use Drupal as a spam
proxy.

CVE-2006-1226

Missing input sanity checks allows attackers to inject arbitrary
web script or HTML.

CVE-2006-1227

Menu items created with the menu.module lacked access control for,
which might allow remote attackers to access administrator pages.

CVE-2006-1228

Markus Petrux discovered a bug in the session fixation which may
allow remote attackers to gain Drupal user privileges.

The old stable distribution (woody) does not contain Drupal packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303297");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-1225", "CVE-2006-1226", "CVE-2006-1227", "CVE-2006-1228");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1007-1 (drupal)");



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
if ((res = isdpkgvuln(pkg:"drupal", ver:"4.5.3-6", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
