# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705249");
  script_version("2022-10-10T10:12:14+0000");
  script_cve_id("CVE-2022-40617");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-08 01:00:06 +0000 (Sat, 08 Oct 2022)");
  script_name("Debian: Security Advisory for strongswan (DSA-5249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5249.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5249-1");
  script_xref(name:"Advisory-ID", value:"DSA-5249-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan'
  package(s) announced via the DSA-5249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lahav Schlesinger discovered a vulnerability in the revocation plugin of
strongSwan, an IKE/IPsec suite.

The revocation plugin uses OCSP URIs and CRL distribution points (CDP) which
come from certificates provided by the remote endpoint. The plugin didn't check
for the certificate chain of trust before using those URIs, so an attacker
could provided a crafted certificate containing URIs pointing to servers under
their control, potentially leading to denial-of-service attacks.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), this problem has been fixed in
version 5.9.1-1+deb11u3.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"charon-cmd", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"charon-systemd", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcharon-extauth-plugins", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-pki", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-scepclient", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"strongswan-swanctl", ver:"5.9.1-1+deb11u3", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
