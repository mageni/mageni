# OpenVAS Vulnerability Test
# $Id: deb_292_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 292-2
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
tag_insight = "Unfortunately yesterday's update for mime-support did not exactly work
as expected, which requires an update.  For completeness we include
the advisory text:

Colin Phipps discovered several problems in mime-support, that contains
support programs for the MIME control files 'mime.types' and 'mailcap'.
When a temporary file is to be used it is created insecurely, allowing
an attacker to overwrite arbitrary under the user id of the person
executing run-mailcap, most probably root.  Additionally the program did
not properly escape shell escape characters when executing a command.
This is unlikely to be exploitable, though.

For the stable distribution (woody) these problems have been fixed in
version 3.18-1.2.

For the old stable distribution (potato) these problems have been
fixed in version 3.9-1.2.

For the unstable distribution (sid) these problems have been
fixed in version 3.22-1 (same as DSA 292-1).

We recommend that you upgrade your mime-support packages.";
tag_summary = "The remote host is missing an update to mime-support
announced via advisory DSA 292-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20292-2";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302975");
 script_version("$Revision: 6616 $");
 script_cve_id("CVE-2003-0214");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 292-2 (mime-support)");



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
if ((res = isdpkgvuln(pkg:"mime-support", ver:"3.9-1.2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mime-support", ver:"3.18-1.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
