# OpenVAS Vulnerability Test
# $Id: deb_067_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 067-1
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
tag_insight = "We have received reports that the 'apache' http daemon, as included in
the Debian 'stable' distribution, is vulnerable to the 'artificially
long slash path directory listing vulnerability' as described in
http://www.securityfocus.com/vdb/bottom.html?vid=2503 .

This vulnerability was announced to bugtraq by Dan Harkless.

Quoting the SecurityFocus entry for this vulnerability:

A problem in the package could allow directory indexing, and path
discovery. In a default configuration, Apache enables mod_dir,
mod_autoindex, and mod_negotiation. However, by placing a custom crafted
request to the Apache server consisting of a long path name created
artificially by using numerous slashes, this can cause these modules to
misbehave, making it possible to escape the error page, and gain a listing
of the directory contents.

This vulnerability makes it possible for a malicious remote user to launch
an information gathering attack, which could potentially result in
compromise of the system. Additionally, this vulnerability affects all
releases of Apache previous to 1.3.19.

This problem has been fixed in apache-ssl 1.3.9-13.3 and apache_1.3.9-14.
We recommend that you upgrade your packages immediately.";
tag_summary = "The remote host is missing an update to apache,apache-ssl
announced via advisory DSA 067-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20067-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304095");
 script_cve_id("CVE-2001-0925");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 067-1 (apache,apache-ssl)");



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
if ((res = isdpkgvuln(pkg:"apache-common", ver:"1.3.9-14", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache-dev", ver:"1.3.9-14", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache", ver:"1.3.9-14", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache-doc", ver:"1.3.9-14", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache-ssl", ver:"1.3.9.13-3", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
