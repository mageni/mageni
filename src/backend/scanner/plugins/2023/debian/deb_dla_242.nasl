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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.242");
  script_cve_id("CVE-2012-3437", "CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-09 12:40:00 +0000 (Tue, 09 May 2017)");

  script_name("Debian: Security Advisory (DLA-242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-242");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-242");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a large number of potential security problems due to insufficient data validation when parsing different input formats. Most of those potential security problems do not have a CVE number assigned.

While the security implications of all of these problems are not all fully known, it is highly recommended to update.

The update fixes the following identified vulnerabilities:

CVE-2012-3437

Incorrect validation of PNG buffer size, leading to DoS using specially crafted PNG files.

CVE-2014-8354

Out of bounds memory access in resize

CVE-2014-8355

Buffer overflow in PCX reader

CVE-2014-8562

Buffer overflow in DCM readers");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++3", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore3-extra", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore3", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand3", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.6.0.4-3+squeeze6", rls:"DEB6"))) {
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
