# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892402");
  script_version("2020-10-08T03:00:22+0000");
  script_cve_id("CVE-2019-11840", "CVE-2019-11841", "CVE-2020-9283");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-10-08 09:52:37 +0000 (Thu, 08 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-08 03:00:22 +0000 (Thu, 08 Oct 2020)");
  script_name("Debian LTS: Security Advisory for golang-go.crypto (DLA-2402-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00014.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2402-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-go.crypto'
  package(s) announced via the DLA-2402-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-11840

An issue was discovered in supplementary Go cryptography libraries, aka
golang-googlecode-go-crypto. If more than 256 GiB of keystream is
generated, or if the counter otherwise grows greater than 32 bits, the amd64
implementation will first generate incorrect output, and then cycle back to
previously generated keystream. Repeated keystream bytes can lead to loss of
confidentiality in encryption applications, or to predictability in CSPRNG
applications.

CVE-2019-11841

A message-forgery issue was discovered in
crypto/openpgp/clearsign/clearsign.go in supplementary Go cryptography
libraries. The 'Hash' Armor Header specifies the message digest
algorithm(s) used for the signature. Since the library skips Armor Header
parsing in general, an attacker can not only embed arbitrary Armor Headers,
but also prepend arbitrary text to cleartext messages without invalidating
the signatures.

CVE-2020-9283

golang.org/x/crypto allows a panic during signature verification in the
golang.org/x/crypto/ssh package. A client can attack an SSH server that accepts
public keys. Also, a server can attack any SSH client.");

  script_tag(name:"affected", value:"'golang-go.crypto' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:0.0~git20170407.0.55a552f+REALLY.0.0~git20161012.0.5f31782-1+deb8u1.

We recommend that you upgrade your golang-go.crypto packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"golang-go.crypto-dev", ver:"1:0.0~git20170407.0.55a552f+REALLY.0.0~git20161012.0.5f31782-1+deb8u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"golang-golang-x-crypto-dev", ver:"1:0.0~git20170407.0.55a552f+REALLY.0.0~git20161012.0.5f31782-1+deb8u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
