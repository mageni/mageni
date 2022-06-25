# OpenVAS Vulnerability Test
# $Id: deb_1473_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1473-1 (scponly)
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
tag_insight = "Joachim Breitner discovered that Subversion support in scponly is
inherently insecure, allowing execution of arbitrary commands.  Further
investigation showed that rsync and Unison support suffer from similar
issues.  This set of issues has been assigned CVE-2007-6350.

In addition, it was discovered that it was possible to invoke with scp
with certain options that may lead to execution of arbitrary commands
(CVE-2007-6415).

This update removes Subversion, rsync and Unison support from the
scponly package, and prevents scp from being invoked with the dangerous
options.

For the stable distribution (etch), these problems have been fixed in
version 4.6-1etch1.

For the old stable distribution (sarge), these problems have been fixed
in version 4.0-1sarge2.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your scponly package.";
tag_summary = "The remote host is missing an update to scponly
announced via advisory DSA 1473-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201473-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304018");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2007-6350", "CVE-2007-6415");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1473-1 (scponly)");



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
if ((res = isdpkgvuln(pkg:"scponly", ver:"4.0-1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scponly", ver:"4.6-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
