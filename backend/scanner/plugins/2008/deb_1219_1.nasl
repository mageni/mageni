# OpenVAS Vulnerability Test
# $Id: deb_1219_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1219-1
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
tag_solution = "For the stable distribution (sarge), these problems have been fixed in
version 4.7-2.2sarge2  Note that binary packages for the mipsel
architecture are not currently available due to technical problems with
the build host.  These packages will be made available as soon as
possible.

For unstable (sid) and the upcoming stable release (etch), these
problems have been fixed in version 4.8.dfsg.1-4

We recommend that you upgrade your texinfo package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201219-1";
tag_summary = "The remote host is missing an update to texinfo
announced via advisory DSA 1219-1.

Multiple vulnerabilities have been found in the GNU texinfo package, a
documentation system for on-line information and printed output.

CVE-2005-3011
Handling of temporary files is performed in an insecure manner, allowing
an attacker to overwrite any file writable by the victim.

CVE-2006-4810
A buffer overflow in util/texindex.c could allow an attacker to execute
arbitrary code with the victim's access rights by inducing the victim to
run texindex or tex2dvi on a specially crafted texinfo file.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301808");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-3011", "CVE-2006-4810");
 script_bugtraq_id(14854,20959);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1219-1 (texinfo)");



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
if ((res = isdpkgvuln(pkg:"info", ver:"4.7-2.2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"texinfo", ver:"4.7-2.2sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
