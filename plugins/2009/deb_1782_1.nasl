# OpenVAS Vulnerability Test
# $Id: deb_1782_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1782-1 (mplayer)
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
tag_insight = "Several vulnerabilities have been discovered in mplayer, a movie player
for Unix-like systems. The Common Vulnerabilities and Exposures project
identifies the following problems:


CVE-2009-0385

It was discovered that watching a malformed 4X movie file could lead to
the execution of arbitrary code.

CVE-2008-4866

It was discovered that multiple buffer overflows could lead to the
execution of arbitrary code.

CVE-2008-5616

It was discovered that watching a malformed TwinVQ file could lead to
the execution of arbitrary code.


For the oldstable distribution (etch), these problems have been fixed
in version 1.0~rc1-12etch7.

For the stable distribution (lenny), mplayer links against
ffmpeg-debian.

For the testing distribution (squeeze) and the unstable distribution
(sid), mplayer links against ffmpeg-debian.


We recommend that you upgrade your mplayer packages.";
tag_summary = "The remote host is missing an update to mplayer
announced via advisory DSA 1782-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201782-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306156");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
 script_cve_id("CVE-2009-0385", "CVE-2008-4866", "CVE-2008-5616");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1782-1 (mplayer)");



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
if ((res = isdpkgvuln(pkg:"mplayer-doc", ver:"1.0~rc1-12etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mplayer", ver:"1.0~rc1-12etch7", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
