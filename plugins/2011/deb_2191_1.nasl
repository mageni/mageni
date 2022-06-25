# OpenVAS Vulnerability Test
# $Id: deb_2191_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2191-1 (proftpd-dfsg)
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
  script_oid("1.3.6.1.4.1.25623.1.0.69327");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7265", "CVE-2010-3867", "CVE-2010-4652", "CVE-2010-4562");
  script_name("Debian Security Advisory DSA 2191-1 (proftpd-dfsg)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202191-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in ProFTPD, a versatile,
virtual-hosting FTP daemon:

CVE-2008-7265

Incorrect handling of the ABOR command could lead to
denial of service through elevated CPU consumption.

CVE-2010-3867

Several directory traversal vulnerabilities have been
discovered in the mod_site_misc module.

CVE-2010-4562

A SQL injection vulnerability was discovered in the
mod_sql module.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.1-17lenny6.

The stable distribution (squeeze) and the unstable distribution (sid)
are not affected, these vulnerabilities have been fixed prior to the
release of Debian 6.0 (squeeze).");

  script_tag(name:"solution", value:"We recommend that you upgrade your proftpd-dfsg packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd-dfsg
announced via advisory DSA 2191-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"proftpd", ver:"1.3.1-17lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.1-17lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.1-17lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.1-17lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.1-17lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.1-17lenny6", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}