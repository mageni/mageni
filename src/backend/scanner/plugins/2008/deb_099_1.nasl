# OpenVAS Vulnerability Test
# $Id: deb_099_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 099-1
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
tag_insight = "zen-parse found a vulnerability in the XChat IRC client that allows an
attacker to take over the users IRC session.

It is possible to trick XChat IRC clients into sending arbitrary
commands to the IRC server they are on, potentially allowing social
engineering attacks, channel takeovers, and denial of service.  This
problem exists in versions 1.4.2 and 1.4.3.  Later versions of XChat
are vulnerable as well, but this behaviour is controlled by the
configuration variable »percascii«, which defaults to 0.  If it is set
to 1 then the problem becomes apparent in 1.6/1.8 a swell.

This problem has been fixed in upstream version 1.8.7 and in version
1.4.3-1 for the current stable Debian release (2.2) with a patch
provided from the upstream author Peter Zelezny.  We recommend that
you upgrade your XChat packages immediately, since this problem is
already actively being exploited.";
tag_summary = "The remote host is missing an update to XChat
announced via advisory DSA 099-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20099-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303837");
 script_cve_id("CVE-2002-0006");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 099-1 (XChat)");



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
if ((res = isdpkgvuln(pkg:"xchat-common", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xchat-gnome", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xchat-text", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xchat", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
