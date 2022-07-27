# OpenVAS Vulnerability Test
# $Id: deb_1270_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1270-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 1.1.3-9sarge6.

For the testing distribution (etch) these problems have been fixed in
version 2.0.4.dfsg.2-6.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.4.dfsg.2-6.

We recommend that you upgrade your OpenOffice.org packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201270-1";
tag_summary = "The remote host is missing an update to openoffice.org
announced via advisory DSA 1270-1.

Several security related problems have been discovered in
OpenOffice.org, the free office suite.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2007-0002

iDefense reported several integer overflow bugs in libwpd, a
library for handling WordPerfect documents that is included in
OpenOffice.org.  Attackers are able to exploit these with
carefully crafted WordPerfect files that could cause an
application linked with libwpd to crash or possibly execute
arbitrary code.

CVE-2007-0238

Next Generation Security discovered that the StarCalc parser in
OpenOffice.org contains an easily exploitable stack overflow that
could be used exploited by a specially crafted document to execute
arbitrary code.

CVE-2007-0239

It has been reported that OpenOffice.org does not escape shell
meta characters and is hence vulnerable to execute arbitrary shell
commands via a specially crafted document after the user clicked
to a prepared link.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303092");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:17:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1270-1 (openoffice.org)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-kn", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-mimelnk", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-thesaurus-en-us", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-bin", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1.1.3-9sarge6", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
