# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705344");
  script_version("2023-02-09T10:17:23+0000");
  script_cve_id("CVE-2022-3437", "CVE-2022-45142");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-09 02:00:12 +0000 (Thu, 09 Feb 2023)");
  script_name("Debian: Security Advisory for heimdal (DSA-5344-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5344.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5344-1");
  script_xref(name:"Advisory-ID", value:"DSA-5344-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heimdal'
  package(s) announced via the DSA-5344-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Helmut Grohne discovered a flaw in Heimdal, an implementation of
Kerberos 5 that aims to be compatible with MIT Kerberos. The backports
of fixes for CVE-2022-3437
accidentally inverted important memory
comparisons in the arcfour-hmac-md5 and rc4-hmac integrity check
handlers for gssapi, resulting in incorrect validation of message
integrity codes.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), this problem has been fixed in
version 7.7.0+dfsg-2+deb11u3.

We recommend that you upgrade your heimdal packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-multidev", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"7.7.0+dfsg-2+deb11u3", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
