# OpenVAS Vulnerability Test
# $Id: deb_1711_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1711-1 (typo3-src)
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
tag_insight = "Several remotely exploitable vulnerabilities have been discovered in the
TYPO3 web content management framework.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2009-0255
Chris John Riley discovered that the TYPO3-wide used encryption key is
generated with an insufficiently random seed resulting in low entropy
which makes it easier for attackers to crack this key.

CVE-2009-0256
Marcus Krause discovered that TYPO3 is not invalidating a supplied session
on authentication which allows an attacker to take over a victims
session via a session fixation attack.

CVE-2009-0257
Multiple cross-site scripting vulnerabilities allow remote attackers to
inject arbitrary web script or HTML via various arguments and user-
supplied strings used in the indexed search system extension, adodb
extension test scripts or the workspace module.

CVE-2009-0258
Mads Olesen discovered a remote command injection vulnerability in
the indexed search system extension which allows attackers to
execute arbitrary code via a crafted file name which is passed
unescaped to various system tools that extract file content for
the indexing.


Because of CVE-2009-0255, please make sure that besides installing
this update, you also create a new encryption key after the
installation.

For the stable distribution (etch) these problems have been fixed in
version 4.0.2+debian-7.

For the unstable distribution (sid) these problems have been fixed in
version 4.2.5-1.

We recommend that you upgrade your TYPO3 packages.";
tag_summary = "The remote host is missing an update to typo3-src
announced via advisory DSA 1711-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201711-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305563");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
 script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
 script_bugtraq_id(33376);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1711-1 (typo3-src)");



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
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.0.2+debian-7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.0", ver:"4.0.2+debian-7", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
