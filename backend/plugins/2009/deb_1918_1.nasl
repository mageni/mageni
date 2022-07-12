# OpenVAS Vulnerability Test
# $Id: deb_1918_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1918-1 (phpmyadmin)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several remote vulnerabilities have been discovered in phpMyAdmin, a tool
to administer MySQL over the web. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-3696

Cross-site scripting (XSS) vulnerability allows remote attackers to
inject arbitrary web script or HTML via a crafted MySQL table name.

CVE-2009-3697

SQL injection vulnerability in the PDF schema generator functionality
allows remote attackers to execute arbitrary SQL commands. This issue
does not apply to the version in Debian 4.0 Etch.

Additionally, extra fortification has been added for the web based setup.php
script. Although the shipped web server configuration should ensure that
this script is protected, in practice this turned out not always to be the
case. The config.inc.php file is not writable anymore by the webserver user
anymore. See README.Debian for details on how to enable the setup.php
script if and when you need it.


For the old stable distribution (etch), these problems have been fixed in
version 2.9.1.1-13.

For the stable distribution (lenny), these problems have been fixed in
version 2.11.8.1-5+lenny3.

For the unstable distribution (sid), these problems have been fixed in
version 3.2.2.1-1.

We recommend that you upgrade your phpmyadmin package.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 1918-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201918-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312168");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-3696", "CVE-2009-3697");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1918-1 (phpmyadmin)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.9.1.1-13", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.11.8.1-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
