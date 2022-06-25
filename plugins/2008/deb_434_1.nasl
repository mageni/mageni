# OpenVAS Vulnerability Test
# $Id: deb_434_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 434-1
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
tag_insight = "Stefan Esser discovered several security related problems in Gaim, a
multi-protocol instant messaging client.  Not all of them are
applicable for the version in Debian stable, but affected the version
in the unstable distribution at least.  The problems were grouped for
the Common Vulnerabilities and Exposures as follows:

CVE-2004-0005

When the Yahoo Messenger handler decodes an octal value for email
notification functions two different kinds of overflows can be
triggered.  When the MIME decoder decoded a quoted printable
encoded string for email notification two other different kinds of
overflows can be triggered.  These problems only affect the
version in the unstable distribution.

CVE-2004-0006

When parsing the cookies within the HTTP reply header of a Yahoo
web connection a buffer overflow can happen.  When parsing the
Yahoo Login Webpage the YMSG protocol overflows stack buffers if
the web page returns oversized values.  When splitting an URL into
its parts a stack overflow can be caused.  These problems only
affect the version in the unstable distribution

When an oversized keyname is read from a Yahoo Messenger packet a
stack overflow can be triggered.  When Gaim is setup to use a HTTP
proxy for connecting to the server a malicious HTTP proxy can
exploit it.  These problems affect all versions Debian ships.
However, the connection to Yahoo doesn't work in the version in
Debian stable.

CVE-2004-0007

Internally data is copied between two tokens into a fixed size
stack buffer without a size check.  This only affects the version
of gaim in the unstable distribution

CVE-2004-0008

When allocating memory for AIM/Oscar DirectIM packets an integer
overflow can happen, resulting in a heap overflow.  This only
affects the version of gaim in the unstable distribution

For the stable distribution (woody) this problem has been fixed in
version 0.58-2.4.

For the unstable distribution (sid) this problem has been fixed in
version 0.75-2.

We recommend that you upgrade your gaim packages.";
tag_summary = "The remote host is missing an update to gaim
announced via advisory DSA 434-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20434-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303535");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0005", "CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 434-1 (gaim)");



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
if ((res = isdpkgvuln(pkg:"gaim", ver:"0.58-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gaim-common", ver:"0.58-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gaim-gnome", ver:"0.58-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
