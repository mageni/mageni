# OpenVAS Vulnerability Test
# $Id: deb_639_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 639-1
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
tag_insight = "Andrew V. Samoilov has noticed that several bugfixes which were
applied to the source by upstream developers of mc, the midnight
commander, a file browser and manager, were not backported to the
current version of mc that Debian ships in their stable release.  The
Common Vulnerabilities and Exposures Project identifies the following
vulnerabilities:

CVE-2004-1004: Multiple format string vulnerabilities
CVE-2004-1005: Multiple buffer overflows
CVE-2004-1009: One infinite loop vulnerability
CVE-2004-1090: Denial of service via  corrupted section header
CVE-2004-1091: Denial of service via null dereference
CVE-2004-1092: Freeing unallocated memory
CVE-2004-1093: Denial of service via use of already freed memory
CVE-2004-1174: Denial of service via manipulating non-existing file handles
CVE-2004-1175: Unintended program execution via insecure filename quoting
CVE-2004-1176: Denial of service via a buffer underflow

For the stable distribution (woody) these problems have been fixed in
version 4.5.55-1.2woody5

For the unstable distribution (sid) these problems should already be
fixed since they were backported from current versions.

We recommend that you upgrade your mc package.";
tag_summary = "The remote host is missing an update to mc
announced via advisory DSA 639-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20639-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303006");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1092", "CVE-2004-1093", "CVE-2004-1174", "CVE-2004-1175", "CVE-2004-1176");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 639-1 (mc)");



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
if ((res = isdpkgvuln(pkg:"gmc", ver:"4.5.55-1.2woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mc", ver:"4.5.55-1.2woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mc-common", ver:"4.5.55-1.2woody5", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
