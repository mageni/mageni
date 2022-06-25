# OpenVAS Vulnerability Test
# $Id: deb_2078_1.nasl 8438 2018-01-16 17:38:23Z teissa $
# Description: Auto-generated from advisory DSA 2078-1 (mapserver)
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
tag_insight = "Several vulnerabilities have been discovered in mapserver, a CGI-based
web framework to publish spatial data and interactive mapping applications.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2010-2539

A stack-based buffer overflow in the msTmpFile function might lead to
arbitrary code execution under some conditions.

CVE-2010-2540

It was discovered that the CGI debug command-line arguments which are
enabled by default are insecure and may allow a remote attacker to
execute arbitrary code. Therefore they have been disabled by default.


For the stable distribution (lenny), this problem has been fixed in
version 5.0.3-3+lenny5.

For the testing distribution (squeeze), this problem has been fixed in
version 5.6.4-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.6.4-1.


We recommend that you upgrade your mapserver packages.";
tag_summary = "The remote host is missing an update to mapserver
announced via advisory DSA 2078-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202078-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313078");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-2539", "CVE-2010-2540");
 script_name("Debian Security Advisory DSA 2078-1 (mapserver)");



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
if ((res = isdpkgvuln(pkg:"libmapscript-ruby", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mapserver-doc", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cgi-mapserver", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mapserver-bin", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perl-mapscript", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php5-mapscript", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-mapscript", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmapscript-ruby1.9", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmapscript-ruby1.8", ver:"5.0.3-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
