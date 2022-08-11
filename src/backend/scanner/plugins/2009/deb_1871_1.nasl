# OpenVAS Vulnerability Test
# $Id: deb_1871_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1871-1 (wordpress)
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
tag_insight = "Several vulnerabilities have been discovered in wordpress, weblog
manager. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-6762

It was discovered that wordpress is prone to an open redirect
vulnerability which allows remote attackers to conduct phishing atacks.

CVE-2008-6767

It was discovered that remote attackers had the ability to trigger an
application upgrade, which could lead to a denial of service attack.

CVE-2009-2334

It was discovered that wordpress lacks authentication checks in the
plugin configuration, which might leak sensitive information.

CVE-2009-2854

It was discovered that wordpress lacks authentication checks in various
actions, thus allowing remote attackers to produce unauthorised edits or
additions.

CVE-2009-2851

It was discovered that the administrator interface is prone to a
cross-site scripting attack.

CVE-2009-2853

It was discovered that remote attackers can gain privileges via certain
direct requests.

CVE-2008-1502

It was discovered that the _bad_protocol_once function in KSES, as used
by wordpress, allows remote attackers to perform cross-site scripting
attacks.

CVE-2008-4106

It was discovered that wordpress lacks certain checks around user
information, which could be used by attackers to change the password of
a user.

CVE-2008-4769

It was discovered that the get_category_template function is prone to a
directory traversal vulnerability, which could lead to the execution of
arbitrary code.

CVE-2008-4796

It was discovered that the _httpsrequest function in the embedded snoopy
version is prone to the execution of arbitrary commands via shell
metacharacters in https URLs.

CVE-2008-5113

It was discovered that wordpress relies on the REQUEST superglobal array
in certain dangerous situations, which makes it easier to perform
attacks via crafted cookies.


For the stable distribution (lenny), these problems have been fixed in
version 2.5.1-11+lenny1.

For the oldstable distribution (etch), these problems have been fixed in
version 2.0.10-1etch4.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 2.8.3-1.


We recommend that you upgrade your wordpress packages.";
tag_summary = "The remote host is missing an update to wordpress
announced via advisory DSA 1871-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201871-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311977");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2008-6762", "CVE-2008-6767", "CVE-2009-2334", "CVE-2009-2854", "CVE-2009-2851", "CVE-2009-2853", "CVE-2008-1502", "CVE-2008-4106", "CVE-2008-4769", "CVE-2008-4796", "CVE-2008-5113");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1871-1 (wordpress)");



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
if ((res = isdpkgvuln(pkg:"wordpress", ver:"2.0.10-1etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wordpress", ver:"2.5.1-11+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
