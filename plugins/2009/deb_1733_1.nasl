# OpenVAS Vulnerability Test
# $Id: deb_1733_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1733-1 (vim)
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
tag_insight = "Several vulnerabilities have been found in vim, an enhanced vi editor.
The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-2712

Jan Minar discovered that vim did not properly sanitise inputs
before invoking the execute or system functions inside vim
scripts. This could lead to the execution of arbitrary code.

CVE-2008-3074

Jan Minar discovered that the tar plugin of vim did not properly
sanitise the filenames in the tar archive or the name of the
archive file itself, making it prone to arbitrary code execution.

CVE-2008-3075

Jan Minar discovered that the zip plugin of vim did not properly
sanitise the filenames in the zip archive or the name of the
archive file itself, making it prone to arbitrary code execution.

CVE-2008-3076

Jan Minar discovered that the netrw plugin of vim did not properly
sanitise the filenames or directory names it is given. This could
lead to the execution of arbitrary code.

CVE-2008-4101

Ben Schmidt discovered that vim did not properly escape characters
when performing keyword or tag lookups. This could lead to the
execution of arbitrary code.


For the stable distribution (lenny), these problems have been fixed in
version 1:7.1.314-3+lenny1, which was already included in the lenny
release.

For the oldstable distribution (etch), these problems have been fixed in
version 1:7.0-122+1etch4.

For the testing distribution (squeeze), these problems have been fixed
in version 1:7.1.314-3+lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 2:7.2.010-1.";
tag_summary = "The remote host is missing an update to vim
announced via advisory DSA 1733-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201733-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306841");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4104", "CVE-2008-4101");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1733-1 (vim)");



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
if ((res = isdpkgvuln(pkg:"vim-gui-common", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-runtime", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-doc", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gnome", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-full", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-common", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-lesstif", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tcl", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-python", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-tiny", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-gtk", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-ruby", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"vim-perl", ver:"7.0-122+1etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
