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
  script_oid("1.3.6.1.4.1.25623.1.0.893187");
  script_version("2022-11-15T02:00:18+0000");
  script_cve_id("CVE-2021-36369");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-15 02:00:18 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-15 02:00:18 +0000 (Tue, 15 Nov 2022)");
  script_name("Debian LTS: Security Advisory for dropbear (DLA-3187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3187-1");
  script_xref(name:"Advisory-ID", value:"DLA-3187-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dropbear'
  package(s) announced via the DLA-3187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Dropbear, a relatively small SSH server and
client. Due to a non-RFC-compliant check of the available authentication
methods in the client-side SSH code, it was possible for an SSH server
to change the login process in its favor. This attack can bypass
additional security measures such as FIDO2 tokens or SSH-Askpass. Thus,
it allows an attacker to abuse a forwarded agent for logging on to
another server unnoticed.");

  script_tag(name:"affected", value:"'dropbear' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
2018.76-5+deb10u2.

We recommend that you upgrade your dropbear packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"dropbear", ver:"2018.76-5+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dropbear-bin", ver:"2018.76-5+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dropbear-initramfs", ver:"2018.76-5+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dropbear-run", ver:"2018.76-5+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
