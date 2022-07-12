# OpenVAS Vulnerability Test
# $Id: deb_1502_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1502-1 (wordpress)
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
tag_insight = "Several remote vulnerabilities have been discovered in wordpress, a weblog
manager.

The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-3238

Cross-site scripting (XSS) vulnerability in functions.php in the default theme
in WordPress allows remote authenticated administrators to inject arbitrary web
script or HTML via the PATH_INFO (REQUEST_URI) to wp-admin/themes.php.

CVE-2007-2821

SQL injection vulnerability in wp-admin/admin-ajax.php in WordPress before 2.2
allows remote attackers to execute arbitrary SQL commands via the cookie
parameter.

CVE-2008-0193

Cross-site scripting (XSS) vulnerability in wp-db-backup.php in WordPress
2.0.11 and earlier allows remote attackers to inject arbitrary web script or
HTML via the backup parameter in a wp-db-backup.php action to
wp-admin/edit.php.

CVE-2008-0194

Directory traversal vulnerability in wp-db-backup.php in WordPress 2.0.3 and
earlier allows remote attackers to read arbitrary files, delete arbitrary
files, and cause a denial of service via a .. (dot dot) in the backup parameter
in a wp-db-backup.php action to wp-admin/edit.php.

For the stable distribution (etch), these problems have been fixed in version
2.0.10-1etch1.  Wordpress is not present in the oldstable distribution (sarge).

We recommend that you upgrade your wordpress package.";
tag_summary = "The remote host is missing an update to wordpress
announced via advisory DSA 1502-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201502-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302670");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-3238", "CVE-2007-2821", "CVE-2008-0193", "CVE-2008-0194");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1502-1 (wordpress)");



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
if ((res = isdpkgvuln(pkg:"wordpress", ver:"2.0.10-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
