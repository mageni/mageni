# OpenVAS Vulnerability Test
# $Id: deb_1775_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1775-1 (php-json-ext)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "It was discovered that php-json-ext, a JSON serialiser for PHP, is
prone to a denial of service attack, when receiving a malformed string
via the json_decode function.

For the oldstable distribution (etch), this problem has been fixed in
version 1.2.1-3.2+etch1.

The stable distribution (lenny) does not contain a separate php-json-ext
package, but includes it in the php5 packages, which will be fixed soon.

The testing distribution (squeeze) and the unstable distribution (sid)
do not contain a separate php-json-ext package, but include it in the
php5 packages.

We recommend that you upgrade your php-json-ext packages.";
tag_summary = "The remote host is missing an update to php-json-ext
announced via advisory DSA 1775-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201775-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308987");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
 script_cve_id("CVE-2009-1271");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1775-1 (php-json-ext)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"php4-json", ver:"1.2.1-3.2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-json", ver:"1.2.1-3.2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
