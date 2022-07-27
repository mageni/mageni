# OpenVAS Vulnerability Test
# $Id: deb_1803_1.nasl 8972 2018-02-28 07:02:10Z cfischer $
# Description: Auto-generated from advisory DSA 1803-1 (nsd, nsd3)
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
tag_insight = "Ilja van Sprundel discovered that a buffer overflow in NSD, an authoritative
name service daemon, allowed to crash the server by sending a crafted packet,
creating a denial of service.

For the old stable distribution (etch), this problem has been fixed in
version 2.3.6-1+etch1 of the nsd package.

For the stable distribution (lenny), this problem has been fixed in
version 2.3.7-1.1+lenny1 of the nsd package and version 3.0.7-3.lenny2
of the nsd3 package.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.7-3 for nsd; nsd3 will be fixed soon.

We recommend that you upgrade your nsd or nsd3 package.";
tag_summary = "The remote host is missing an update to nsd, nsd3
announced via advisory DSA 1803-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201803-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310198");
 script_version("$Revision: 8972 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-28 08:02:10 +0100 (Wed, 28 Feb 2018) $");
 script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 1803-1 (nsd, nsd3)");
 script_cve_id("CVE-2009-1755");

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
if ((res = isdpkgvuln(pkg:"nsd", ver:"2.3.6-1+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nsd3", ver:"3.0.7-3.lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nsd", ver:"2.3.7-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
