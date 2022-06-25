# OpenVAS Vulnerability Test
# $Id: deb_2033_1.nasl 8438 2018-01-16 17:38:23Z teissa $
# Description: Auto-generated from advisory DSA 2033-1 (ejabberd)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "It was discovered that in ejabberd, a distributed XMPP/Jabber server
written in Erlang, a problem in ejabberd_c2s.erl allows remote
authenticated users to cause a denial of service by sending a large
number of c2s (client2server) messages; that triggers an overload of the
queue, which in turn causes a crash of the ejabberd daemon.

For the stable distribution (lenny), this problem has been fixed in
version 2.0.1-6+lenny2.

For the testing distribution (squeeze), this problem has been fixed in
version 2.1.2-2.

For the testing distribution (sid), this problem has been fixed in
version 2.1.2-2.

We recommend that you upgrade your ejabberd packages.";
tag_summary = "The remote host is missing an update to ejabberd
announced via advisory DSA 2033-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202033-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313401");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_cve_id("CVE-2010-0305");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2033-1 (ejabberd)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"ejabberd", ver:"2.0.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
