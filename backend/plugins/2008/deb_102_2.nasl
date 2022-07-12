# OpenVAS Vulnerability Test
# $Id: deb_102_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 102-2
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
tag_insight = "Basically, this is the same Security Advisory as DSA 102-1, except
that the uploaded binary packages really fix the problem this time.
Unfortunately the bugfix from DSA 102-1 wasn't propagated properly due
to a packaging bug.  While the file parsetime.y was fixed, and
yy.tab.c should be generated from it, yy.tab.c from the original
source was still used.  This has been fixed now.

The original advisory said:

zen-parse found a bug in the current implementation of at which leads
into a heap corruption vulnerability which in turn could potentially
lead into an exploit of the daemon user.

This has been fixed in at 3.1.8-10.2 for the stable Debian release and
3.1.8-11 for the unstable and testing release.  Packages for unstable
have just been uploaded into <http://incoming.debian.org/>.  We
recommend that you upgrade your at packages immediately since an
exploit has already been published.";
tag_summary = "The remote host is missing an update to at
announced via advisory DSA 102-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20102-2";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303130");
 script_cve_id("CVE-2002-0004");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 102-2 (at)");



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
if ((res = isdpkgvuln(pkg:"at", ver:"3.1.8-10.2", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
