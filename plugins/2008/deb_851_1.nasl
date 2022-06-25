# OpenVAS Vulnerability Test
# $Id: deb_851_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 851-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 2.0-1sarge1.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.2-1.

We recommend that you upgrade your openvpn package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20851-1";
tag_summary = "The remote host is missing an update to openvpn
announced via advisory DSA 851-1.

Several security related problems have been discovered in openvpn, a
Virtual Private Network daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2005-2531
Wrong processing of failed certificate authentication when running
with verb 0 and without TLS authentication can lead to a denial
of service by disconnecting the wrong client.

CVE-2005-2532
Wrong handling of packets that can't be decrypted on the server
can lead to the disconnection of unrelated clients.

CVE-2005-2533
When running in dev tap Ethernet bridging mode, openvpn can
exhaust its memory by receiving a large number of spoofed MAC
addresses and hence denying service.

CVE-2005-2534
Simultaneous TCP connections from multiple clients with the same
client certificate can cause a denial of service when
--duplicate-cn is not enabled.

The old stable distribution (woody) does not contain openvpn packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301932");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2531", "CVE-2005-2532", "CVE-2005-2533", "CVE-2005-2534");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 851-1 (openvpn)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"openvpn", ver:"2.0-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
