# OpenVAS Vulnerability Test
# $Id: deb_230_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 230-1
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
tag_insight = "Two vulnerabilities have been discovered in Bugzilla, a web-based bug
tracking system, by its authors.  The Common Vulnerabilities and
Exposures Project identifies the following vulnerabilities:

* CVE-2003-0012 (BugTraq ID 6502): The provided data collection
script intended to be run as a nightly cron job changes the
permissions of the data/mining directory to be world-writable every
time it runs.  This would enable local users to alter or delete the
collected data.

* CVE-2003-0013 (BugTraq ID 6501): The default .htaccess scripts
provided by checksetup.pl do not block access to backups of the
localconfig file that might be created by editors such as vi or
emacs (typically these will have a .swp or ~ suffix).  This allows
an end user to download one of the backup copies and potentially
obtain your database password.

This does not affect the Debian installation because there is no
.htaccess as all data file aren't under the CGI path as they are on
the standard Bugzilla package.  Additionally, the configuration is
in /etc/bugzilla/localconfig and hence outside of the web directory.

For the current stable distribution (woody) these problems have been
fixed in version 2.14.2-0woody4.

The old stable distribution (potato) does not contain a Bugzilla
package.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your bugzilla packages.";
tag_summary = "The remote host is missing an update to bugzilla
announced via advisory DSA 230-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20230-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300914");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0012", "CVE-2003-0013");
 script_bugtraq_id(6501,6502);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 230-1 (bugzilla)");



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
if ((res = isdpkgvuln(pkg:"bugzilla-doc", ver:"2.14.2-0woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bugzilla", ver:"2.14.2-0woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
