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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.248");
  script_cve_id("CVE-2015-3456");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-248");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-248");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the qemu virtualisation solution:

CVE-2015-3456

Jason Geffner discovered a buffer overflow in the emulated floppy disk drive, resulting in the potential execution of arbitrary code.

Despite the end-of-life of qemu support in the old-oldstable distribution (squeeze-lts), this problem has been fixed in version 0.12.5+dfsg-3squeeze4 of the qemu source package due to its severity (the so-called VENOM vulnerability).

Further problems may still be present in the qemu package in the old-oldstable distribution (squeeze-lts) and users who need to rely on qemu are encouraged to upgrade to a newer version of Debian.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libqemu-dev", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-keymaps", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"0.12.5+dfsg-3squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
