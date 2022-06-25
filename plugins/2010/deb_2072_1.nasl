# OpenVAS Vulnerability Test
# $Id: deb_2072_1.nasl 8447 2018-01-17 16:12:19Z teissa $
# Description: Auto-generated from advisory DSA 2072-1 (libpng)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in libpng, a library for
reading and writing PNG files. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2010-1205

It was discovered a buffer overflow in libpng which allows remote
attackers to execute arbitrary code via a PNG image that triggers
an additional data row.


CVE-2010-2249

It was discovered a memory leak in libpng which allows remote
attackers to cause a denial of service (memory consumption and
application crash) via a PNG image containing malformed Physical
Scale (aka sCAL) chunks


For the stable distribution (lenny), these problems have been fixed in
version 1.2.27-2+lenny4.

For the testing (squeeze) and unstable (sid) distribution, these
problems have been fixed in version 1.2.44-1

We recommend that you upgrade your libpng package.";
tag_summary = "The remote host is missing an update to libpng
announced via advisory DSA 2072-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202072-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314046");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1205", "CVE-2010-2249");
 script_name("Debian Security Advisory DSA 2072-1 (libpng)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libpng3", ver:"1.2.27-2+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.27-2+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.27-2+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
