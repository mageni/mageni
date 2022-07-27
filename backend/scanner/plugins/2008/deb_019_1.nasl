# OpenVAS Vulnerability Test
# $Id: deb_019_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 019-1
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
tag_insight = "WireX discovered a potential temporary file race condition in the way
that squid sends out email messages notifying the administrator about
updating the program.  This could lead to arbitrary files to get
overwritten.  However the code would only be executed if running a
very bleeding edge release of squid, running a server whose time is
set some number of months in the past and squid is crashing.  Read it
as hardly to exploit.  This version also contains more upstream
bugfixes wrt. dots in hostnames and unproper HTML quoting.

We recommend you upgrade your squid package..";
tag_summary = "The remote host is missing an update to squid
announced via advisory DSA 019-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20019-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300429");
 script_cve_id("CVE-2001-0142");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"1.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 019-1 (squid)");



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
if ((res = isdpkgvuln(pkg:"squid-cgi", ver:"2.2.5-3.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squid", ver:"2.2.5-3.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squidclient", ver:"2.2.5-3.1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
