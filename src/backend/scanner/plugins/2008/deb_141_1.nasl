# OpenVAS Vulnerability Test
# $Id: deb_141_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 141-1
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
tag_insight = "Eckehard Berns discovered a buffer overflow in the munpack program
which is used for decoding (respectively) binary files in MIME
(Multipurpose Internet Mail Extensions) format mail messages.  If
munpack is run on an appropriately malformed email (or news article)
then it will crash, and perhaps can be made to run arbitrary code.

Herbert Xu reported a second vulnerability which affected malformed
filenames that refer to files in upper directories like ../a.  The
security impact is limited, though, because only a single leading
../ was accepted and only new files can be created (i.e. no files
will be overwritten).

Both problems were been fixed in version 1.5-5potato2 for the old
stable distribution (potato), in version 1.5-7woody2 for the current
stable distribution (woody) and in version 1.5-9 for the unstable
distribution (sid).

We recommend that you upgrade your mpack package immediately.";
tag_summary = "The remote host is missing an update to mpack
announced via advisory DSA 141-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20141-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303512");
 script_cve_id("CVE-2002-1425");
 script_bugtraq_id(5385);
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_name("Debian Security Advisory DSA 141-1 (mpack)");



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
if ((res = isdpkgvuln(pkg:"mpack", ver:"1.5-5potato2", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mpack", ver:"1.5-7woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
