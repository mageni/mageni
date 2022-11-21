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
  script_oid("1.3.6.1.4.1.25623.1.0.705286");
  script_version("2022-11-20T02:00:04+0000");
  script_cve_id("CVE-2022-42898");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-20 02:00:04 +0000 (Sun, 20 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-20 02:00:04 +0000 (Sun, 20 Nov 2022)");
  script_name("Debian: Security Advisory for krb5 (DSA-5286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5286.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5286-1");
  script_xref(name:"Advisory-ID", value:"DSA-5286-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5'
  package(s) announced via the DSA-5286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Greg Hudson discovered integer overflow flaws in the PAC parsing in
krb5, the MIT implementation of Kerberos, which may result in remote
code execution (in a KDC, kadmin, or GSS or Kerberos application server
process), information exposure (to a cross-realm KDC acting
maliciously), or denial of service (KDC or kadmind process crash).");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), this problem has been fixed in
version 1.18.3-6+deb11u3.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-doc", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-k5tls", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-kpropd", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-locales", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-otp", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"krb5-user", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt-mit12", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv-mit12", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkdb5-10", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrad-dev", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrad0", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.18.3-6+deb11u3", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
