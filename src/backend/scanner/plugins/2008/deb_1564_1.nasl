# OpenVAS Vulnerability Test
# $Id: deb_1564_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1564-1 (wordpress)
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
tag_insight = "Several remote vulnerabilities have been discovered in wordpress,
a weblog manager. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-3639

Insufficient input sanitising allowed for remote attackers to
redirect visitors to external websites.

CVE-2007-4153

Multiple cross-site scripting vulnerabilities allowed remote
authenticated administrators to inject arbitrary web script or HTML.

CVE-2007-4154

SQL injection vulnerability allowed allowed remote authenticated
administrators to execute arbitrary SQL commands.

CVE-2007-0540

WordPress allows remote attackers to cause a denial of service
(bandwidth or thread consumption) via pingback service calls with
a source URI that corresponds to a file with a binary content type,
which is downloaded even though it cannot contain usable pingback data.

[no CVE name yet]

Insufficient input sanitising caused an attacker with a normal user
account to access the administrative interface.


For the stable distribution (etch), these problems have been fixed in
version 2.0.10-1etch2.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.3-1.

We recommend that you upgrade your wordpress package.";
tag_summary = "The remote host is missing an update to wordpress
announced via advisory DSA 1564-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201564-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302294");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-05-12 19:53:28 +0200 (Mon, 12 May 2008)");
 script_cve_id("CVE-2007-3639", "CVE-2007-4153", "CVE-2007-4154", "CVE-2007-0540");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1564-1 (wordpress)");



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
if ((res = isdpkgvuln(pkg:"wordpress", ver:"2.0.10-1etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
