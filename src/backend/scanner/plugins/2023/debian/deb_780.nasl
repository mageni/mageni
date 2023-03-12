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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2005.780");
  script_cve_id("CVE-2005-2097");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-780)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-780");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-780");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdegraphics' package(s) announced via the DSA-780 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bug has been discovered in the font handling code in xpdf, which is also present in kpdf, the PDF viewer for KDE. A specially crafted PDF file could cause infinite resource consumption, in terms of both CPU and disk space.

The oldstable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in version 3.3.2-2sarge1.

For the unstable distribution (sid) this problem will be fixed as soon as the necessary libraries have made their C++ ABI transition.

We recommend that you upgrade your kpdf package.");

  script_tag(name:"affected", value:"'kdegraphics' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"kamera", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kcoloredit", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-dev", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics-kfile-plugins", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdegraphics", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdvi", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfax", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kgamma", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kghostview", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kiconedit", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmrml", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kolourpaint", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kooka", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpdf", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpovmodeler", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kruler", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksnapshot", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksvg", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kuickshow", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kview", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kviewshell", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkscan-dev", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkscan1", ver:"4:3.3.2-2sarge1", rls:"DEB3.1"))) {
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
