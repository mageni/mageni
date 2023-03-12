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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.1154");
  script_cve_id("CVE-2017-15930");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-30 03:15:00 +0000 (Sun, 30 Jun 2019)");

  script_name("Debian: Security Advisory (DLA-1154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1154");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1154");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DLA-1154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in graphicsmagick.

CVE-2017-14103

The ReadJNGImage and ReadOneJNGImage functions in coders/png.c in GraphicsMagick 1.3.26 do not properly manage image pointers after certain error conditions, which allows remote attackers to conduct use-after-free attacks via a crafted file, related to a ReadMNGImage out-of-order CloseBlob call. NOTE: this vulnerability exists because of an incomplete fix for CVE-2017-11403.

CVE-2017-14314

Off-by-one error in the DrawImage function in magick/render.c in GraphicsMagick 1.3.26 allows remote attackers to cause a denial of service (DrawDashPolygon heap-based buffer over-read and application crash) via a crafted file.

CVE-2017-14504

ReadPNMImage in coders/pnm.c in GraphicsMagick 1.3.26 does not ensure the correct number of colors for the XV 332 format, leading to a NULL Pointer Dereference.

CVE-2017-14733

ReadRLEImage in coders/rle.c in GraphicsMagick 1.3.26 mishandles RLE headers that specify too few colors, which allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted file.

CVE-2017-14994

ReadDCMImage in coders/dcm.c in GraphicsMagick 1.3.26 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted DICOM image, related to the ability of DCM_ReadNonNativeImages to yield an image list with zero frames.

CVE-2017-14997

GraphicsMagick 1.3.26 allows remote attackers to cause a denial of service (excessive memory allocation) because of an integer underflow in ReadPICTImage in coders/pict.c.

CVE-2017-15930

In ReadOneJNGImage in coders/png.c in GraphicsMagick 1.3.26, a Null Pointer Dereference occurs while transferring JPEG scanlines, related to a PixelPacket pointer.

For Debian 7 Wheezy, CVE-2017-15930 has been fixed in version 1.3.16-1.1+deb7u12. The other security issues were fixed in 1.3.16-1.1+deb7u10 on 10 Oct 2017 in DLA-1130-1 but that announcement was never sent out so this advisory also contains the notice about those vulnerabilities.

We recommend that you upgrade your graphicsmagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.16-1.1+deb7u12", rls:"DEB7"))) {
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
