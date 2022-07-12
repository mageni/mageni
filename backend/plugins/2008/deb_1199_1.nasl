# OpenVAS Vulnerability Test
# $Id: deb_1199_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1199-1
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
tag_solution = "For the stable distribution (sarge), these problems have been fixed in
version 1.180-3sarge1

Webmin is not included in unstable (sid) or testing (etch), so these
problems are not present.

We recommend that you upgrade your webmin (1.180-3sarge1) package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201199-1";
tag_summary = "The remote host is missing an update to webmin
announced via advisory DSA 1199-1.

Several vulnerabilities have been identified in webmin, a web-based
administration toolkit.

CVE-2005-3912
A format string vulnerability in miniserv.pl could allow an
attacker to cause a denial of service by crashing the
application or exhausting system resources, and could
potentially allow arbitrary code execution.

CVE-2006-3392
Improper input sanitization in miniserv.pl could allow an
attacker to read arbitrary files on the webmin host by providing
a specially crafted URL path to the miniserv http server.

CVE-2006-4542
Improper handling of null characters in URLs in miniserv.pl
could allow an attacker to conduct cross-site scripting attacks,
read CGI program source code, list local directories, and
potentially execute arbirary code.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302703");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-3912", "CVE-2006-3392", "CVE-2006-4542");
 script_bugtraq_id(15629,18744,19820);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1199-1 (webmin)");



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
if ((res = isdpkgvuln(pkg:"webmin-core", ver:"1.180-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"webmin", ver:"1.180-3sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
