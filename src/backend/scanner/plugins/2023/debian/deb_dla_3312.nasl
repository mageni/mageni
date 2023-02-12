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
  script_oid("1.3.6.1.4.1.25623.1.0.893312");
  script_version("2023-02-09T10:17:23+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-09 02:00:18 +0000 (Thu, 09 Feb 2023)");
  script_name("Debian LTS: Security Advisory for shim (DLA-3312-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/02/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3312-1");
  script_xref(name:"Advisory-ID", value:"DLA-3312-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim'
  package(s) announced via the DLA-3312-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This release fixes various issues in shim bootloader and updates it to
a supported version. Older versions of the shim may eventually be blocked
by Secure Boot, so it is strongly advised for Secure Boot enabled systems
to upgrade to this newer version to keep the system bootable.

Additionally, this update blocks old, insecure versions of GRUB. Thus an
update to a signed GRUB 2.06-3~deb10u3 package as released in DLA 3190-2
must be in place prior to updating the shim packages.");

  script_tag(name:"affected", value:"'shim' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
15.7-1~deb10u1.

We recommend that you upgrade your shim packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"shim-helpers-amd64-signed-template", ver:"15.7-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"shim-helpers-arm64-signed-template", ver:"15.7-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"shim-helpers-i386-signed-template", ver:"15.7-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"shim-unsigned", ver:"15.7-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
