# OpenVAS Vulnerability Test
# $Id: deb_042_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 042-1
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
tag_insight = "Klaus Frank has found a vulnerability in the way gnuserv handled
remote connections.  Gnuserv is a remote control facility for Emacsen
which is available as standalone program as well as included in
XEmacs21.  Gnuserv has a buffer for which insufficient boundary checks
were made.  Unfortunately this buffer affected access control to
gnuserv which is using a MIT-MAGIC-COOCKIE based system.  It is
possible to overflow the buffer containing the cookie and foozle
cookie comparison.

Gnuserv was derived from emacsserver which is part of GNU Emacs.  It's
was reworked completely and not much is to be left over from its time
as part of GNU Emacs.  Therefore the versions of emacssserver in both
Emacs19 and Emacs20 doesn't look vulnerable to this bug, they don't
even provide a MIT-MAGIC-COOKIE based mechanism.

This could lead into a remote user issue commands under
the UID of the person running gnuserv.

We recommend you upgrade your xemacs21 and gnuserv packages immediately.";
tag_summary = "The remote host is missing an update to gnuserv, xemacs21
announced via advisory DSA 042-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20042-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301917");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 042-1 (gnuserv, xemacs21)");



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
if ((res = isdpkgvuln(pkg:"xemacs21-support", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xemacs21-supportel", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xemacs21", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnuserv", ver:"2.1alpha-5.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xemacs21-bin", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xemacs21-mule-canna-wnn", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xemacs21-mule", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xemacs21-nomule", ver:"21.1.10-5", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
