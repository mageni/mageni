# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2463-1 (samba)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.71340");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2012-2111");
  script_version("2021-11-23T15:20:34+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2012-05-31 11:42:39 -0400 (Thu, 31 May 2012)");
  script_name("Debian Security Advisory DSA 2463-1 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202463-1");
  script_tag(name:"insight", value:"Ivano Cristofolini discovered that insufficient security checks in
Samba's handling of LSA RPC calls could lead to privilege escalation
by gaining the take ownership privilege.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.6~dfsg-3squeeze8.

For the unstable distribution (sid), this problem has been fixed in
version 3.6.5-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your samba packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to samba
announced via advisory DSA 2463-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"swat", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:3.5.6~dfsg-3squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}