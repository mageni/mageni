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
  script_oid("1.3.6.1.4.1.25623.1.0.705347");
  script_cve_id("CVE-2022-44267", "CVE-2022-44268");
  script_tag(name:"creation_date", value:"2023-02-16 02:00:08 +0000 (Thu, 16 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 19:20:00 +0000 (Tue, 14 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-5347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5347");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5347");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/imagemagick");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-5347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bryan Gonzalez discovered that the PNG support in Imagemagick could be tricked into embedding the content of an arbitrary file when converting an image file.

For the stable distribution (bullseye), these problems have been fixed in version 8:6.9.11.60+dfsg-1.3+deb11u1.

We recommend that you upgrade your imagemagick packages.

For the detailed security status of imagemagick please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-common", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-doc", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6-headers", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-8", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-8", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6-extra", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-6", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.9.11.60+dfsg-1.3+deb11u1", rls:"DEB11"))) {
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
