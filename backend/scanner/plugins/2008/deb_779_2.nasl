# OpenVAS Vulnerability Test
# $Id: deb_779_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 779-2
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
version 1.0.4-2sarge3.

For the unstable distribution (sid) these problems have been fixed in
version 1.0.6-1.

We recommend that you upgrade your Mozilla Firefox packages.


 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20779-2";
tag_summary = "The remote host is missing an update to mozilla-firefox
announced via advisory DSA 779-2.

We experienced that the update for Mozilla Firefox from DSA 779-1
unfortunately was a regression in several cases.  Since the usual
praxis of backporting apparently does not work, this update is
basically version 1.0.6 with the version number rolled back, and hence
still named 1.0.4-*.  For completeness below is the original advisory
text:

Several problems have been discovered in Mozilla Firefox, a
lightweight web browser based on Mozilla.  The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2005-2260

The browser user interface does not properly distinguish between
user-generated events and untrusted synthetic events, which makes
it easier for remote attackers to perform dangerous actions that
normally could only be performed manually by the user.

CVE-2005-2261

XML scripts ran even when Javascript disabled.

CVE-2005-2262

The user can be tricked to executing arbitrary JavaScript code by
using a JavaScript URL as wallpaper.

CVE-2005-2263

It is possible for a remote attacker to execute a callback
function in the context of another domain (i.e. frame).

CVE-2005-2264

By opening a malicious link in the sidebar it is possible for
remote attackers to steal sensitive information.

CVE-2005-2265

Missing input sanitising of InstallVersion.compareTo() can cause
the application to crash.

CVE-2005-2266

Remote attackers could steal sensitive information such as cookies
and passwords from web sites by accessing data in alien frames.

CVE-2005-2267

By using standalone applications such as Flash and QuickTime to
open a javascript: URL, it is possible for a remote attacker to
steal sensitive information and possibly execute arbitrary code.

CVE-2005-2268

It is possible for a Javascript dialog box to spoof a dialog box
from a trusted site and facilitates phishing attacks.

CVE-2005-2269

Remote attackers could modify certain tag properties of DOM nodes
that could lead to the execution of arbitrary script or code.

CVE-2005-2270

The Mozilla browser familie does not properly clone base objects,
which allows remote attackers to execute arbitrary code.

The old stable distribution (woody) is not affected by these problems.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301429");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
 script_bugtraq_id(14242);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 779-2 (mozilla-firefox)");



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
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
