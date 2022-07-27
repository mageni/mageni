# OpenVAS Vulnerability Test
# $Id: deb_1406_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1406-1
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
tag_insight = "Several remote vulnerabilities have been discovered in the Horde web
application framework. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2006-3548

Moritz Naumann discovered that Horde allows remote attackers
to inject arbitrary web script or HTML in the context of a logged
in user (cross site scripting).

This vulnerability applies to oldstable (sarge) only.

CVE-2006-3549

Moritz Naumann discovered that Horde does not properly restrict
its image proxy, allowing remote attackers to use the server as a
proxy.

This vulnerability applies to oldstable (sarge) only.

CVE-2006-4256

Marc Ruef discovered that Horde allows remote attackers to
include web pages from other sites, which could be useful for
phishing attacks.

This vulnerability applies to oldstable (sarge) only.

CVE-2007-1473

Moritz Naumann discovered that Horde allows remote attackers
to inject arbitrary web script or HTML in the context of a logged
in user (cross site scripting).

This vulnerability applies to both stable (etch) and oldstable (sarge).

CVE-2007-1474

iDefense discovered that the cleanup cron script in Horde
allows local users to delete arbitrary files.

This vulnerability applies to oldstable (sarge) only.


For the old stable distribution (sarge) these problems have been fixed in
version 3.0.4-4sarge6.

For the stable distribution (etch) these problems have been fixed in
version 3.1.3-4etch1.

For the unstable distribution (sid) these problems have been fixed in
version 3.1.4-1.

We recommend that you upgrade your horde3 package.";
tag_summary = "The remote host is missing an update to horde3
announced via advisory DSA 1406-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201406-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302220");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-3548", "CVE-2006-3549", "CVE-2006-4256", "CVE-2007-1473", "CVE-2007-1474");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1406-1 (horde3)");



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
if ((res = isdpkgvuln(pkg:"horde3", ver:"3.0.4-4sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"horde3", ver:"3.1.3-4etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
