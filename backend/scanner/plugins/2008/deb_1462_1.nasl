# OpenVAS Vulnerability Test
# $Id: deb_1462_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1462-1 (hplip)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Kees Cook discovered that the hpssd tool of the HP Linux Printing and
Imaging System (HPLIP) performs insufficient input sanitising of shell
meta characters, which may result in local privilege escalation to
the hplip user.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.10-4.3.

For the stable distribution (etch), this problem has been fixed in
version 1.6.10-3etch1.

The old stable distribution (sarge) is not affected by this problem.

We recommend that you upgrade your hplip packages.";
tag_summary = "The remote host is missing an update to hplip
announced via advisory DSA 1462-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201462-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303414");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2007-5208");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1462-1 (hplip)");



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
if ((res = isdpkgvuln(pkg:"hpijs-ppds", ver:"2.6.10+1.6.10-3etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-data", ver:"1.6.10-3etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-doc", ver:"1.6.10-3etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-dbg", ver:"1.6.10-3etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip", ver:"1.6.10-3etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hpijs", ver:"2.6.10+1.6.10-3etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
