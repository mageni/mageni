# OpenVAS Vulnerability Test
# $Id: deb_1501_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1501-1 (dspam)
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
tag_insight = "Tobias Gruetzmacher discovered that a Debian-provided CRON script in dspam,
a statistical spam filter, included a database password on the command line
when using the MySQL backend. This allowed a local attacker to read the
contents of the dspam database, such as emails.

For the stable distribution (etch), this problem has been fixed in version
3.6.8-5etch1. Packages for the mipsel architecture will be added as soon
as they become available.

The old stable distribution (sarge) does not contain the dspam package.

For the unstable distribution (sid), this problem has been fixed in
version 3.6.8-5.1.


We recommend that you upgrade your dspam package.";
tag_summary = "The remote host is missing an update to dspam
announced via advisory DSA 1501-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201501-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303550");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-6418");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 1501-1 (dspam)");



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
if ((res = isdpkgvuln(pkg:"dspam-doc", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dspam-webfrontend", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdspam7", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdspam7-drv-mysql", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdspam7-drv-pgsql", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdspam7-dev", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdspam7-drv-db4", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dspam", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdspam7-drv-sqlite3", ver:"3.6.8-5etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
