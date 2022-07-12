# OpenVAS Vulnerability Test
# $Id: deb_2044_1.nasl 8972 2018-02-28 07:02:10Z cfischer $
# Description: Auto-generated from advisory DSA 2044-1 (mplayer)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "tixxDZ (DZCORE labs) discovered a vulnerability in the mplayer movie
player.  Missing data validation in mplayer's real data transport (RDT)
implementation enable an integer underflow and consequently an unbounded
buffer operation.  A maliciously crafted stream could thus enable an
attacker to execute arbitrary code.

No Common Vulnerabilities and Exposures project identifier is available for
this issue.

For the stable distribution (lenny), this problem has been fixed in version
1.0~rc2-17+lenny3.2.

We recommend that you upgrade your mplayer packages.";
tag_summary = "The remote host is missing an update to mplayer
announced via advisory DSA 2044-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202044-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313092");
 script_version("$Revision: 8972 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-28 08:02:10 +0100 (Wed, 28 Feb 2018) $");
 script_tag(name:"creation_date", value:"2010-05-14 20:09:58 +0200 (Fri, 14 May 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 2044-1 (mplayer)");
 script_cve_id("CVE-2010-2062");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mplayer-doc", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mplayer", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mplayer-dbg", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
