# OpenVAS Vulnerability Test
# $Id: deb_732_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 732-1
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
tag_insight = "infamous41md discovered several vulnerabilities in the GNU mailutils
package which contains utilities for handling mail.  These problems
can lead to a denial of service or the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities.

CVE-2005-1520

Buffer overflow mail header handling may allow a remote attacker
to execute commands with the privileges of the targeted user.

CVE-2005-1521

Combined integer and heap overflow in the fetch routine can lead
to the execution of arbitrary code.

CVE-2005-1522

Denial of service in the fetch routine.

CVE-2005-1523

Format string vulnerability can lead to the execution of arbitrary
code.

For the stable distribution (woody) these problems have been fixed in
version 20020409-1woody2.

For the testing distribution (sarge) these problems have been fixed in
version 0.6.1-4.

For the unstable distribution (sid) these problems have been fixed in
version 0.6.1-4.

We recommend that you upgrade your mailutils packages.";
tag_summary = "The remote host is missing an update to mailutils
announced via advisory DSA 732-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20732-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302610");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-1520", "CVE-2005-1521", "CVE-2005-1522", "CVE-2005-1523");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 732-1 (mailutils)");



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
if ((res = isdpkgvuln(pkg:"mailutils-doc", ver:"20020409-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmailutils0", ver:"20020409-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmailutils0-dev", ver:"20020409-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mailutils", ver:"20020409-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mailutils-imap4d", ver:"20020409-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mailutils-pop3d", ver:"20020409-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
