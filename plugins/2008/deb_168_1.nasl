# OpenVAS Vulnerability Test
# $Id: deb_168_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 168-1
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
tag_insight = "Wojciech Purczynski found out that it is possible for scripts to pass
arbitrary text to sendmail as commandline extension when sending a
mail through PHP even when safe_mode is turned on.  Passing 5th
argument should be disabled if PHP is configured in safe_mode, which
is the case for newer PHP versions and for the versions below.  This
does not affect PHP3, though.

Wojciech Purczynski also found out that arbitrary ASCII control
characters may be injected into string arguments of mail() function.
If mail() arguments are taken from user's input it may give the user
ability to alter message content including mail headers.

Ulf Harnhammar discovered that file() and fopen() are vulnerable to
CRLF injection.  An attacker could use it to escape certain
restrictions and add arbitrary text to alleged HTTP requests that are
passed through.

However this only happens if something is passed to these functions
which is neither a valid file name nor a valid url.  Any string that
contains control chars cannot be a valid url.  Before you pass a
string that should be an url to any function you must use urlencode()
to encode it.

Three problems have been identified in PHP:

1. The mail() function can allow arbitrary email headers to be
specified if a recipient address or subject contains CR/LF
characters.

2. The mail() function does not properly disable the passing of
arbitrary command-line options to sendmail when running in Safe
Mode.

3. The fopen() function, when retrieving a URL, can allow manipulation
of the request for the resource through a URL containing CR/LF
characters.  For example, headers could be added to an HTTP
request.

These problems have been fixed in version 3.0.18-23.1woody1 for PHP3
and 4.1.2-5 for PHP4 for the current stable distribution (woody), in
version 3.0.18-0potato1.2 for PHP3 and 4.0.3pl1-0potato4 for PHP4 in
the old stable distribution (potato) and in version 3.0.18-23.2 for
PHP3 and 4.2.3-3 for PHP4 for the unstable distribution (sid).

We recommend that you upgrade your PHP packages.";
tag_summary = "The remote host is missing an update to PHP3, PHP4
announced via advisory DSA 168-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20168-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301770");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-0985", "CVE-2002-0986");
 script_bugtraq_id(5681);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 168-1 (PHP3, PHP4)");



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
if ((res = isdpkgvuln(pkg:"php3", ver:"3.0.18-0potato1.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php3-cgi", ver:"3.0.18-0potato1.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4", ver:"4.0.3pl1-0potato4", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-cgi", ver:"4.0.3pl1-0potato4", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php3", ver:"3.0.18-23.1woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php3-cgi", ver:"3.0.18-23.1woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"caudium-php4", ver:"4.1.2-5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4", ver:"4.1.2-5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-cgi", ver:"4.1.2-5", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
