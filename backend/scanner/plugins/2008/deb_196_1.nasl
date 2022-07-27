# OpenVAS Vulnerability Test
# $Id: deb_196_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 196-1
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
tag_insight = "[Bind version 9, the bind9 package, is not affected by these problems.]

ISS X-Force has discovered several serious vulnerabilities in the Berkeley
Internet Name Domain Server (BIND).  BIND is the most common implementation
of the DNS (Domain Name Service) protocol, which is used on the vast
majority of DNS servers on the Internet.  DNS is a vital Internet protocol
that maintains a database of easy-to-remember domain names (host names) and
their corresponding numerical IP addresses.

Circumstancial evidence suggests that the Internet Software Consortium
(ISC), maintainers of BIND, was made aware of these issues in mid-October.
Distributors of Open Source operating systems, including Debian, were
notified of these vulnerabilities via CERT about 12 hours before the release
of the advisories on November 12th.  This notification did not include any
details that allowed us to identify the vulnerable code, much less prepare
timely fixes.

Unfortunately ISS and the ISC released their security advisories with only
descriptions of the vulnerabilities, without any patches.  Even though there
were no signs that these exploits are known to the black-hat community, and
there were no reports of active attacks, such attacks could have been
developed in the meantime - with no fixes available.

We can all express our regret at the inability of the ironically named
Internet Software Consortium to work with the Internet community in handling
this problem.  Hopefully this will not become a model for dealing with
security issues in the future.

The Common Vulnerabilities and Exposures (CVE) project identified the
following vulnerabilities:

1. CVE-2002-1219: A buffer overflow in BIND 8 versions 8.3.3 and earlier
allows a remote attacker to execute arbitrary code via a certain DNS
server response containing SIG resource records (RR).  This buffer
overflow can be exploited to obtain access to the victim host under the
account the named process is running with, usually root.

2. CVE-2002-1220: BIND 8 versions 8.3.x through 8.3.3 allows a remote
attacker to cause a denial of service (termination due to assertion
failure) via a request for a subdomain that does not exist, with an OPT
resource record with a large UDP payload size.

3. CVE-2002-1221: BIND 8 versions 8.x through 8.3.3 allows a remote attacker
to cause a denial of service (crash) via SIG RR elements with invalid
expiry times, which are removed from the internal BIND database and later
cause a null dereference.

These problems have been fixed in version 8.3.3-2.0woody1 for the current
stable distribution (woody), in 8.2.3-0.potato.3 for the previous stable
distribution (potato) and in version 8.3.3-3 for the unstable distribution
(sid).  The fixed packages for unstable will enter the archive today.

We recommend that you upgrade your bind package immediately, update to";
tag_summary = "The remote host is missing an update to bind
announced via advisory DSA 196-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20196-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300205");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1219", "CVE-2002-1220", "CVE-2002-1221");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 196-1 (bind)");



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
if ((res = isdpkgvuln(pkg:"task-dns-server", ver:"8.2.3-0.potato.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind-doc", ver:"8.2.3-0.potato.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind-dev", ver:"8.2.3-0.potato.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind", ver:"8.2.3-0.potato.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"8.2.3-0.potato.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind-doc", ver:"8.3.3-2.0woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind-dev", ver:"8.3.3-2.0woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind", ver:"8.3.3-2.0woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"8.2.3-0.potato.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
