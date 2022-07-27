# OpenVAS Vulnerability Test
# $Id: deb_956_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 956-1
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-3sarge1.

For the unstable distribution (sid) this problem has been fixed in
version 2.0.1cdbs-4.

We recommend that you upgrade your lsh-server package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20956-1";
tag_summary = "The remote host is missing an update to lsh-utils
announced via advisory DSA 956-1.

Stefan Pfetzing discovered that lshd, a Secure Shell v2 (SSH2)
protocol server, leaks a couple of file descriptors, related to the
randomness generator, to user shells which are started by lshd.  A
local attacker can truncate the server's seed file, which may prevent
the server from starting, and with some more effort, maybe also crack
session keys.

After applying this update, you should remove the server's seed file
(/var/spool/lsh/yarrow-seed-file) and then regenerate it with
lsh-make-seed --server as root.

For security reasons, lsh-make-seed really needs to be run from the
console of the system you are running it on.  If you run lsh-make-seed
using a remote shell, the timing information lsh-make-seed uses for
its random seed creation is likely to be screwed.  If need be, you can
generate the random seed on a different system than that which it will
eventually be on, by installing the lsh-utils package and running
lsh-make-seed -o my-other-server-seed-file.  You may then transfer
the seed to the destination system as using a secure connection.

The old stable distribution (woody) may not be affected by this problem.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300312");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(16357);
 script_cve_id("CVE-2006-0353");
 script_tag(name:"cvss_base", value:"3.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
 script_name("Debian Security Advisory DSA 956-1 (lsh-utils)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"lsh-utils-doc", ver:"2.0.1-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lsh-client", ver:"2.0.1-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lsh-server", ver:"2.0.1-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lsh-utils", ver:"2.0.1-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
