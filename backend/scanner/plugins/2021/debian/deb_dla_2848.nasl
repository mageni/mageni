# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892848");
  script_version("2021-12-21T03:03:22+0000");
  script_cve_id("CVE-2019-13115", "CVE-2019-17498");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-12-21 03:03:22 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-12-20 09:56:53 +0000 (Mon, 20 Dec 2021)");
  script_name("Debian LTS: Security Advisory for libssh2 (DLA-2848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/12/msg00013.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2848-1");
  script_xref(name:"Advisory-ID", value:"DLA-2848-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2'
  package(s) announced via the DLA-2848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been discovered in libssh2, a client-side C library implementing
the SSH2 protocol:

CVE-2019-13115:
kex_method_diffie_hellman_group_exchange_sha256_key_exchange in kex.c has
an integer overflow that could lead to an out-of-bounds read in the way
packets are read from the server. A remote attacker who compromises a
SSH server may be able to disclose sensitive information or cause a denial
of service condition on the client system when a user connects to the server.

CVE-2019-17498:
SSH_MSG_DISCONNECT logic in packet.c has an integer overflow in a bounds check,
enabling an attacker to specify an arbitrary (out-of-bounds) offset for a
subsequent memory read. A crafted SSH server may be able to disclose sensitive
information or cause a denial of service condition on the client system when
a user connects to the server.");

  script_tag(name:"affected", value:"'libssh2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.7.0-1+deb9u2.

We recommend that you upgrade your libssh2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libssh2-1", ver:"1.7.0-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dbg", ver:"1.7.0-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dev", ver:"1.7.0-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
