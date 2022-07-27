# OpenVAS Vulnerability Test
# $Id: deb_1370_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1370-1
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
tag_insight = "Several remote vulnerabilities have been discovered in phpMyAdmin, a
program to administrate MySQL over the web. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2007-1325

The PMA_ArrayWalkRecursive function in libraries/common.lib.php
does not limit recursion on arrays provided by users, which allows
context-dependent attackers to cause a denial of service (web
server crash) via an array with many dimensions.

This issue affects only the stable distribution (Etch).

CVE-2007-1395

Incomplete blacklist vulnerability in index.php allows remote
attackers to conduct cross-site scripting (XSS) attacks by
injecting arbitrary JavaScript or HTML in a (1) db or (2) table
parameter value followed by an uppercase </SCRIPT> end tag,
which bypasses the protection against lowercase </script>.

This issue affects only the stable distribution (Etch).

CVE-2007-2245

Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary web script or HTML via (1) the
fieldkey parameter to browse_foreigners.php or (2) certain input
to the PMA_sanitize function.

CVE-2006-6942

Multiple cross-site scripting (XSS) vulnerabilities allow remote
attackers to inject arbitrary HTML or web script via (1) a comment
for a table name, as exploited through (a) db_operations.php,
(2) the db parameter to (b) db_create.php, (3) the newname parameter
to db_operations.php, the (4) query_history_latest,
(5) query_history_latest_db, and (6) querydisplay_tab parameters to
(c) querywindow.php, and (7) the pos parameter to (d) sql.php.

This issue affects only the oldstable distribution (Sarge).

CVE-2006-6944

phpMyAdmin allows remote attackers to bypass Allow/Deny access rules
that use IP addresses via false headers.

This issue affects only the oldstable distribution (Sarge).

For the stable distribution (etch) these problems have been fixed in
version 2.9.0.3-4.

For the old stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge4.

For the unstable distribution (sid) these problems have been fixed in
version 2.10.1-1.

We recommend that you upgrade your phpmyadmin packages.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 1370-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201370-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302696");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-6942", "CVE-2006-6944", "CVE-2007-1325", "CVE-2007-1395", "CVE-2007-2245");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1370-1 (phpmyadmin)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.6.2-3sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.9.1.1-4", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
