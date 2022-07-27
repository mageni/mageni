# OpenVAS Vulnerability Test
# $Id: deb_1496_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1496-1 (mplayer)
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
tag_insight = "Several buffer overflows have been discovered in the MPlayer movie player,
which might lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0485

Felipe Manzano and Anibal Sacco discovered a buffer overflow in
the demuxer for MOV files.

CVE-2008-0486

Reimar Doeffinger discovered a buffer overflow in the FLAC header
parsing.

CVE-2008-0629

Adam Bozanich discovered a buffer overflow in the CDDB access code.

CVE-2008-0630

Adam Bozanich discovered a buffer overflow in URL parsing.


For the stable distribution (etch), these problems have been fixed in
version 1.0~rc1-12etch2.

The old stable distribution (sarge) doesn't contain mplayer.

We recommend that you upgrade your mplayer packages.";
tag_summary = "The remote host is missing an update to mplayer
announced via advisory DSA 1496-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201496-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302543");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-15 23:29:21 +0100 (Fri, 15 Feb 2008)");
 script_cve_id("CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1496-1 (mplayer)");



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
if ((res = isdpkgvuln(pkg:"mplayer-doc", ver:"1.0~rc1-12etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mplayer", ver:"1.0~rc1-12etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
