# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2339-1 (nss)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.70553");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3640");
  script_version("2021-11-23T15:20:34+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2012-02-11 02:28:18 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2339-1 (nss)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202339-1");
  script_tag(name:"insight", value:"This update to the NSS cryptographic libraries revokes the trust in the
DigiCert Sdn. Bhd certificate authority.

This update also fixes an insecure load path for pkcs11.txt configuration
file (CVE-2011-3640).

For the oldstable distribution (lenny), this problem has been fixed in
version 3.12.3.1-0lenny7.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze4.

For the unstable distribution (sid), this problem has been fixed in
version 3.13.1.with.ckbi.1.88-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your nss packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to nss
announced via advisory DSA 2339-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.3.1-0lenny7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.3.1-0lenny7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.3.1-0lenny7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.3.1-0lenny7", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.8-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.8-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.8-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.8-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
