# OpenVAS Vulnerability Test
# $Id: deb_1641_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1641-1 (phpmyadmin)
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
tag_insight = "Several remote vulnerabilities have been discovered in phpMyAdmin, a
tool to administrate MySQL databases over the web. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4096

Remote authenticated users could execute arbitrary code on the
host running phpMyAdmin through manipulation of a script parameter.

CVE-2008-3457

Cross site scripting through the setup script was possible in
rare circumstances.

CVE-2008-3456

Protection has been added against remote websites loading phpMyAdmin
into a frameset.

CVE-2008-3197

Cross site request forgery allowed remote attackers to create a new
database, but not perform any other action on it.

For the stable distribution (etch), these problems have been fixed in
version 4:2.9.1.1-8.

For the unstable distribution (sid), these problems have been fixed in
version 4:2.11.8.1-2.

We recommend that you upgrade your phpmyadmin package.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 1641-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201641-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300143");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-09-24 17:42:31 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2008-3197", "CVE-2008-3456", "CVE-2008-3457", "CVE-2008-4096");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1641-1 (phpmyadmin)");



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
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.9.1.1-8", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
