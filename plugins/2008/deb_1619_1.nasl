# OpenVAS Vulnerability Test
# $Id: deb_1619_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1619-1 (python-dns)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Multiple weaknesses have been identified in PyDNS, a DNS client
implementation for the Python language.  Dan Kaminsky identified a
practical vector of DNS response spoofing and cache poisoning,
exploiting the limited entropy in a DNS transaction ID and lack of
UDP source port randomization in many DNS implementations.  Scott
Kitterman noted that python-dns is vulnerable to this predictability,
as it randomizes neither its transaction ID nor its source port.
Taken together, this lack of entropy leaves applications using
python-dns to perform DNS queries highly susceptible to response
forgery.

The Common Vulnerabilities and Exposures project identifies this
class of weakness as CVE-2008-1447.

For the stable distribution (etch), these problems have been fixed in
version 2.3.0-5.2+etch1.

We recommend that you upgrade your python-dns package.";
tag_summary = "The remote host is missing an update to python-dns
announced via advisory DSA 1619-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201619-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304082");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
 script_cve_id("CVE-2008-1447");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1619-1 (python-dns)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"python-dns", ver:"2.3.0-5.2+etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
