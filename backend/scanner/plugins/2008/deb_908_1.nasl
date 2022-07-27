# OpenVAS Vulnerability Test
# $Id: deb_908_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 908-1
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
tag_insight = "Colin Leroy discovered several buffer overflows in a number of
importer routines in sylpheed-claws, an extended version of the
Sylpheed mail client, that could lead to the execution of arbitrary
code.

The following matrix explains which versions fix this vulnerability

                     old stable (woody)   stable (sarge)  unstable (sid)
sylpheed               0.7.4-4woody1      1.0.4-1sarge1      2.0.4-1
sylpheed-gtk1              n/a                 n/a           1.0.6-1
sylpheed-claws       0.7.4claws-3woody1   1.0.4-1sarge1      1.0.5-2
sylpheed-claws-gtk2        n/a                 n/a          1.9.100-1

We recommend that you upgrade your sylpheed-claws package.";
tag_summary = "The remote host is missing an update to sylpheed-claws
announced via advisory DSA 908-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20908-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300552");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(15363);
 script_cve_id("CVE-2005-3354");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 908-1 (sylpheed-claws)");



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
if ((res = isdpkgvuln(pkg:"sylpheed-claws", ver:"0.7.4claws-3woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-i18n", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-plugins", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-scripts", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsylpheed-claws-dev", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-clamav", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-dillo-viewer", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-image-viewer", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-pgpmime", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-spamassassin", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sylpheed-claws-trayicon", ver:"1.0.4-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
