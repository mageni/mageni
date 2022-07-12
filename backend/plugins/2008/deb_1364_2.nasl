# OpenVAS Vulnerability Test
# $Id: deb_1364_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1364-2
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
tag_insight = "Several vulnerabilities have been discovered in the vim editor. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2953

Ulf Harnhammar discovered that a format string flaw in helptags_one() from
src/ex_cmds.c (triggered through the helptags command) can lead to the
execution of arbitrary code.

CVE-2007-2438

Editors often provide a way to embed editor configuration commands (aka
modelines) which are executed once a file is opened. Harmful commands
are filtered by a sandbox mechanism. It was discovered that function
calls to writefile(), feedkeys() and system() were not filtered, allowing
shell command execution with a carefully crafted file opened in vim.

This updated advisory repairs issues with missing files in the packages
for the oldstable distribution (sarge) for the alpha, mips, and mipsel
architectures.

For the oldstable distribution (sarge) these problems have been fixed in
version 6.3-071+1sarge2. Sarge is not affected by CVE-2007-2438.

For the stable distribution (etch) these problems have been fixed
in version 7.0-122+1etch3.

For the unstable distribution (sid) these problems have been fixed in
version 7.1-056+1.

We recommend that you upgrade your vim packages.";
tag_summary = "The remote host is missing an update to vim
announced via advisory DSA 1364-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201364-2";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301544");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-2438", "CVE-2007-2953");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1364-2 (vim)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"vim-common", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-full", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-lesstif", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"6.3-071+1sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gui-common", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-runtime", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-common", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-full", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-lesstif", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tiny", ver:"7.0-122+1etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
