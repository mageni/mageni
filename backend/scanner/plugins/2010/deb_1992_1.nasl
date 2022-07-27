# OpenVAS Vulnerability Test
# $Id: deb_1992_1.nasl 8457 2018-01-18 07:58:32Z teissa $
# Description: Auto-generated from advisory DSA 1992-1 (chrony)
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
tag_insight = "Several vulnerabilities have been discovered in chrony, a pair of programs
which are used to maintain the accuracy of the system clock on a computer.
This issues are similar to the NTP security flaw CVE-2009-3563.  The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0292

chronyd replies to all cmdmon packets with NOHOSTACCESS messages even for
unauthorized hosts.  An attacker can abuse this behaviour to force two
chronyd instances to play packet ping-pong by sending such a packet with
spoofed source address and port.  This results in high CPU and network
usage and thus denial of service conditions.

CVE-2010-0293

The client logging facility of chronyd doesn't limit memory that is used
to store client information.  An attacker can cause chronyd to allocate
large amounts of memory by sending NTP or cmdmon packets with spoofed
source addresses resulting in memory exhaustion.

CVE-2010-0294

chronyd lacks of a rate limit control to the syslog facility when logging
received packets from unauthorized hosts.  This allows an attacker to
cause denial of service conditions via filling up the logs and thus disk
space by repeatedly sending invalid cmdmon packets.


For the oldstable distribution (etch), this problem has been fixed in
version 1.21z-5+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 1.23-6+lenny1.

For the testing (squeeze) and unstable (sid) distribution, this problem
will be fixed soon.


We recommend that you upgrade your chrony packages.";
tag_summary = "The remote host is missing an update to chrony
announced via advisory DSA 1992-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201992-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312916");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
 script_cve_id("CVE-2010-0292", "CVE-2010-0293", "CVE-2010-0294", "CVE-2009-3563");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_name("Debian Security Advisory DSA 1992-1 (chrony)");



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
if ((res = isdpkgvuln(pkg:"chrony", ver:"1.21z-5+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chrony", ver:"1.23-6+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
