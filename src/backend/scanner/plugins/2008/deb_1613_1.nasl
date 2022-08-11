# OpenVAS Vulnerability Test
# $Id: deb_1613_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1613-1 (libgd2)
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
tag_insight = "Multiple vulnerabilities have been identified in libgd2, a library
for programmatic graphics creation and manipulation.  The Common
Vulnerabilities and Exposures project identifies the following three
issues:

CVE-2007-2445

Grayscale PNG files containing invalid tRNS chunk CRC values
could cause a denial of service (crash), if a maliciously
crafted image is loaded into an application using libgd.

CVE-2007-3476

An array indexing error in libgd's GIF handling could induce a
denial of service (crash with heap corruption) if exceptionally
large color index values are supplied in a maliciously crafted
GIF image file.

CVE-2007-3477

The imagearc() and imagefilledarc() routines in libgd allow
an attacker in control of the parameters used to specify
the degrees of arc for those drawing functions to perform
a denial of service attack (excessive CPU consumption).

CVE-2007-3996

Multiple integer overflows exist in libgd's image resizing and
creation routines; these weaknesses allow an attacker in control
of the parameters passed to those routines to induce a crash or
execute arbitrary code with the privileges of the user running
an application or interpreter linked against libgd2.

For the stable distribution (etch), these problems have been fixed in
version 2.0.33-5.2etch1.  For the unstable distribution (sid), the
problem has been fixed in version 2.0.35.dfsg-1.

We recommend that you upgrade your libgd2 packages.";
tag_summary = "The remote host is missing an update to libgd2
announced via advisory DSA 1613-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201613-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303584");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
 script_cve_id("CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3996", "CVE-2007-2445");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1613-1 (libgd2)");



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
if ((res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.0.33-5.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd-tools", ver:"2.0.33-5.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.33-5.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.33-5.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.0.33-5.2etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
