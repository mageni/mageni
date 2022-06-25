# OpenVAS Vulnerability Test
# $Id: deb_379_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 379-1
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
tag_insight = "Alexander Hvostov, Julien Blache and Aurelien Jarno discovered several
security-related problems in the sane-backends package, which contains
an API library for scanners including a scanning daemon (in the
package libsane) that can be remotely exploited.  Thes problems allow
a remote attacker to cause a segfault fault and/or consume arbitrary
amounts of memory.  The attack is successful, even if the attacker's
computer isn't listed in saned.conf.

You are only vulnerable if you actually run saned e.g. in xinetd or
inetd.  If the entries in the configuration file of xinetd or inetd
respectively are commented out or do not exist, you are safe.

Try telnet localhost 6566 on the server that may run saned.  If you
get connection refused saned is not running and you are safe.

The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2003-0773:

saned checks the identity (IP address) of the remote host only
after the first communication took place (SANE_NET_INIT).  So
everyone can send that RPC, even if the remote host is not allowed
to scan (not listed in saned.conf).

CVE-2003-0774:

saned lacks error checking nearly everywhere in the code. So
connection drops are detected very late. If the drop of the
connection isn't detected, the access to the internal wire buffer
leaves the limits of the allocated memory. So random memory after
the wire buffer is read which will be followed by a segmentation
fault.

CVE-2003-0775:

If saned expects strings, it mallocs the memory necessary to store
the complete string after it receives the size of the string. If
the connection was dropped before transmitting the size, malloc
will reserve an arbitrary size of memory. Depending on that size
and the amount of memory available either malloc fails (->saned
quits nicely) or a huge amount of memory is allocated. Swapping and
and OOM measures may occur depending on the kernel.

CVE-2003-0776:

saned doesn't check the validity of the RPC numbers it gets before
getting the parameters.

CVE-2003-0777:

If debug messages are enabled and a connection is dropped,
non-null-terminated strings may be printed and segamentation faults
may occur.

CVE-2003-0778:

It's possible to allocate an arbitrary amount of memory on the
server running saned even if the connection isn't dropped.  At the
moment this can not easily be fixed according to the author.
Better limit the total amount of memory saned may use (ulimit).

For the stable distribution (woody) this problem has been
fixed in version 1.0.7-4.

For the unstable distribution (sid) this problem has been fixed in
version 1.0.11-1 and later.

We recommend that you upgrade your libsane packages.";
tag_summary = "The remote host is missing an update to sane-backends
announced via advisory DSA 379-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20379-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300289");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0773", "CVE-2003-0774", "CVE-2003-0775", "CVE-2003-0776", "CVE-2003-0777", "CVE-2003-0778");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 379-1 (sane-backends)");



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
if ((res = isdpkgvuln(pkg:"libsane", ver:"1.0.7-4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsane-dev", ver:"1.0.7-4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
