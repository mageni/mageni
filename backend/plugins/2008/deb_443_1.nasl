# OpenVAS Vulnerability Test
# $Id: deb_443_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 443-1
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
tag_insight = "A number of vulnerabilities have been discovered in XFree86:

CVE-2004-0083: Buffer overflow in ReadFontAlias from dirfile.c of
XFree86 4.1.0 through 4.3.0 allows local users and remote attackers to
execute arbitrary code via a font alias file (font.alias) with a long
token, a different vulnerability than CVE-2004-0084.

CVE-2004-0084: Buffer overflow in the ReadFontAlias function in XFree86
4.1.0 to 4.3.0, when using the CopyISOLatin1Lowered function, allows
local or remote authenticated users to execute arbitrary code via a
malformed entry in the font alias (font.alias) file, a different
vulnerability than CVE-2004-0083.

CVE-2004-0106: Miscellaneous additional flaws in XFree86's handling of
font files.

CVE-2003-0690: xdm does not verify whether the pam_setcred function call
succeeds, which may allow attackers to gain root privileges by
triggering error conditions within PAM modules, as demonstrated in
certain configurations of the MIT pam_krb5 module.

CVE-2004-0093, CVE-2004-0094: Denial-of-service attacks against the X
server by clients using the GLX extension and Direct Rendering
Infrastructure are possible due to unchecked client data (out-of-bounds
array indexes [CVE-2004-0093] and integer signedness errors
[CVE-2004-0094]).

Exploitation of CVE-2004-0083, CVE-2004-0084, CVE-2004-0106,
CVE-2004-0093 and CVE-2004-0094 would require a connection to the X
server.  By default, display managers in Debian start the X server
with a configuration which only accepts local connections, but if the
configuration is changed to allow remote connections, or X servers are
started by other means, then these bugs could be exploited remotely.
Since the X server usually runs with root privileges, these bugs could
potentially be exploited to gain root privileges.

No attack vector for CVE-2003-0690 is known at this time.

For the stable distribution (woody) these problems have been fixed in
version 4.1.0-16woody3.

For the unstable distribution (sid) these problems have been fixed in
version 4.3.0-2.

We recommend that you update your xfree86 package.";
tag_summary = "The remote host is missing an update to xfree86
announced via advisory DSA 443-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20443-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301598");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0690", "CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106", "CVE-2004-0093", "CVE-2004-0094");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 443-1 (xfree86)");



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
if ((res = isdpkgvuln(pkg:"x-window-system", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-100dpi-transcoded", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-100dpi", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-75dpi-transcoded", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-75dpi", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-base-transcoded", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-base", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-cyrillic", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-pex", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-scalable", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfree86-common", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlib6g-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlib6g", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xspecs", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lbxproxy", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdps-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdps1", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdps1-dbg", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw6", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw6-dbg", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw6-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw7", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw7-dbg", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxaw7-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proxymngr", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"twm", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"x-window-system-core", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xbase-clients", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdm", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfwp", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa3", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibmesa3-dbg", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibosmesa-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibosmesa3", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibosmesa3-dbg", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-dbg", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-dev", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xlibs-pic", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xmh", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xprt", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-common", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xfree86", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xterm", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xutils", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"4.1.0-16woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
