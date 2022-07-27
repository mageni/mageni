# OpenVAS Vulnerability Test
# $Id: deb_576_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 576-1
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
tag_insight = "Several security vulnerabilities have been discovered in Squid, the
internet object cache, the popular WWW proxy cache.  The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-1999-0710

It is possible to bypass access lists and scan arbitrary hosts and
ports in the network through cachemgr.cgi, which is installed by
default.  This update disables this feature and introduces a
configuration file (/etc/squid/cachemgr.conf) to control
this behavier.

CVE-2004-0918

The asn_parse_header function (asn1.c) in the SNMP module for
Squid allows remote attackers to cause a denial of service via
certain SNMP packets with negative length fields that causes a
memory allocation error.

For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody4.

For the unstable distribution (sid) these problems have been fixed in
version 2.5.7-1.

We recommend that you upgrade your squid package.";
tag_summary = "The remote host is missing an update to squid
announced via advisory DSA 576-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20576-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301644");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-1999-0710", "CVE-2004-0918");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 576-1 (squid)");



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
if ((res = isdpkgvuln(pkg:"squid", ver:"2.4.6-2woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid-cgi", ver:"2.4.6-2woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squidclient", ver:"2.4.6-2woody4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
