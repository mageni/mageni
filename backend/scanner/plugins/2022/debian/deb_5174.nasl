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
  script_oid("1.3.6.1.4.1.25623.1.0.705174");
  script_version("2022-07-05T08:13:05+0000");
  script_cve_id("CVE-2022-34903");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-05 08:13:05 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 01:00:04 +0000 (Tue, 05 Jul 2022)");
  script_name("Debian: Security Advisory for gnupg2 (DSA-5174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5174.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5174-1");
  script_xref(name:"Advisory-ID", value:"DSA-5174-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2'
  package(s) announced via the DSA-5174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Demi Marie Obenour discovered a flaw in GnuPG, allowing for signature
spoofing via arbitrary injection into the status line. An attacker who
controls the secret part of any signing-capable key or subkey in the
victim's keyring, can take advantage of this flaw to provide a
correctly-formed signature that some software, including gpgme, will
accept to have validity and signer fingerprint chosen from the attacker.");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), this problem has been fixed
in version 2.2.12-1+deb10u2.

For the stable distribution (bullseye), this problem has been fixed in
version 2.2.27-2+deb11u2.

We recommend that you upgrade your gnupg2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"dirmngr", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg-agent", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg-l10n", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg-utils", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg-agent", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg-wks-client", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg-wks-server", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgconf", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgsm", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv-static", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv-udeb", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv-win32", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv2", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scdaemon", ver:"2.2.27-2+deb11u2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dirmngr", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg-agent", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg-l10n", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg-utils", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg-agent", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg-wks-client", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpg-wks-server", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgconf", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgsm", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv-static", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv-win32", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gpgv2", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scdaemon", ver:"2.2.12-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
