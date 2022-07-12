# OpenVAS Vulnerability Test
# $Id: deb_958_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 958-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-5.

For the unstable distribution (sid) these problems have been fixed in
version 4.5.6-1.

We recommend that you upgrade your drupal package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20958-1";
tag_summary = "The remote host is missing an update to drupal
announced via advisory DSA 958-1.

Several security related problems have been discovered in drupal, a
fully-featured content management/discussion engine.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:

CVE-2005-3973

Several cross-site scripting vulnerabilities allow remote
attackers to inject arbitrary web script or HTML.

CVE-2005-3974

When running on PHP5, Drupal does not correctly enforce user
privileges, which allows remote attackers to bypass the access
user profiles permission.

CVE-2005-3975

An interpretation conflict allows remote authenticated users to
inject arbitrary web script or HTML via HTML in a file with a GIF
or JPEG file extension.

The old stable distribution (woody) does not contain drupal packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300522");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-3973", "CVE-2005-3974", "CVE-2005-3975");
 script_bugtraq_id(15674,15677,15663);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_name("Debian Security Advisory DSA 958-1 (drupal)");



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
if ((res = isdpkgvuln(pkg:"drupal", ver:"4.5.3-5", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
