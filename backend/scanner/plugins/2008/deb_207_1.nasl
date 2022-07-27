# OpenVAS Vulnerability Test
# $Id: deb_207_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 207-1
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
tag_insight = "The SuSE security team discovered a vulnerability in kpathsea library
(libkpathsea) which is used by xdvi and dvips.  Both programs call the
system() function insecurely, which allows a remote attacker to
execute arbitrary commands via cleverly crafted DVI files.

If dvips is used in a print filter, this allows a local or remote
attacker with print permission execute arbitrary code as the printer
user (usually lp).

This problem has been fixed in version 1.0.7+20011202-7.1for the
current stable distribution (woody), in version 1.0.6-7.3 for the old
stable distribution (potato) and in version 1.0.7+20021025-4 for the
unstable distribution (sid).  xdvik-ja and dvipsk-ja are vulnerable as
well, but link to the kpathsea library dynamically and will
automatically be fixed after a new libkpathsea is installed.

We recommend that you upgrade your tetex-lib package immediately.";
tag_summary = "The remote host is missing an update to tetex-bin
announced via advisory DSA 207-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20207-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300799");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(5978);
 script_cve_id("CVE-2002-0836");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 207-1 (tetex-bin)");



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
if ((res = isdpkgvuln(pkg:"tetex-bin", ver:"1.0.6-7.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tetex-dev", ver:"1.0.6-7.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tetex-lib", ver:"1.0.6-7.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkpathsea-dev", ver:"1.0.7+20011202-7.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkpathsea3", ver:"1.0.7+20011202-7.1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tetex-bin", ver:"1.0.7+20011202-7.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
