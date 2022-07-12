# OpenVAS Vulnerability Test
# $Id: deb_2315_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2315-1 (openoffice.org)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70404");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_cve_id("CVE-2011-2713");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 2315-1 (openoffice.org)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202315-1");
  script_tag(name:"insight", value:"Red Hat, Inc. security researcher Huzaifa Sidhpurwala reported multiple
vulnerabilities in the binary Microsoft Word (doc) file format importer
of OpenOffice.org, a full-featured office productivity suite that
provides a near drop-in replacement for Microsoft(R) Office.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:2.4.1+dfsg-1+lenny12.

For the stable distribution (squeeze), this problem has been fixed in
version 1:3.2.1-11+squeeze4.

For the testing distribution (wheezy), and the unstable distribution (sid),
this problem will be fixed soon.
We recommend that you upgrade your openoffice.org packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to openoffice.org
announced via advisory DSA 2315-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"broffice.org", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cli-uno-bridge", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmythes-dev", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-basetypes1.0-cil", ver:"1.0.10.0+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-cppuhelper1.0-cil", ver:"1.0.13.0+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-types1.1-cil", ver:"1.1.13.0+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-ure1.0-cil", ver:"1.0.13.0+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mozilla-openoffice.org", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-base-core", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-emailmerge", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-filter-binfilter", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-headless", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-eu", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-gl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-pt", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-mr-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ro", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sr", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sr-cs", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-uz", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-ogltrans", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-presentation-minimizer", ver:"1.0+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-report-builder", ver:"1:1.0.2+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-report-builder-bin", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-sdbc-postgresql", ver:"1:0.7.6+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-andromeda", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-tango", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-uno", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1:2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ure", ver:"1.4+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ure-dbg", ver:"1.4+OOo2.4.1+dfsg-1+lenny12", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"broffice.org", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cli-uno-bridge", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-basetypes1.0-cil", ver:"1.0.17.0+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-cppuhelper1.0-cil", ver:"1.0.20.0+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-oootypes1.0-cil", ver:"1.0.6.0+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-ure1.0-cil", ver:"1.0.20.0+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libuno-cli-uretypes1.0-cil", ver:"1.0.6.0+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mozilla-openoffice.org", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-base-core", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-emailmerge", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-filter-binfilter", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ca", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-el", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-eu", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-fi", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-gl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-om", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-pt", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-as", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ast", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-gu", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-id", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ml", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-mn", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-mr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-mr-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-oc", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-om", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-or", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ro", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-si", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ta", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-te", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ug", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-uz", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-mysql-connector", ver:"1.0.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-ogltrans", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-pdfimport", ver:"1.0.2+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-presentation-minimizer", ver:"1.0.2+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-presenter-console", ver:"1.1.0+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-report-builder", ver:"1:1.2.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-report-builder-bin", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-sdbc-postgresql", ver:"1:0.7.6+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-andromeda", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-galaxy", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-oxygen", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-style-tango", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-wiki-publisher", ver:"1.1.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-uno", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1:3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uno-libs3", ver:"1.6.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uno-libs3-dbg", ver:"1.6.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ure", ver:"1.6.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ure-dbg", ver:"1.6.1+OOo3.2.1-11+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}