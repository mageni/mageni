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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.484");
  script_cve_id("CVE-2015-8808", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718", "CVE-2016-5239");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 13:29:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Debian: Security Advisory (DLA-484)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-484");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-484");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DLA-484 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in graphicsmagick a tool to manipulate image files.

GraphicsMagick is a fork of ImageMagick and also affected by vulnerabilities collectively known as ImageTragick, that are the consequence of lack of sanitization of untrusted input. An attacker with control on the image input could, with the privileges of the user running the application, execute code (CVE-2016-3714), make HTTP GET or FTP requests (CVE-2016-3718), or delete (CVE-2016-3715), move (CVE-2016-3716), or read (CVE-2016-3717), local files.

To address these concerns the following changes have been made:

Remove automatic detection/execution of MVG based on file header or file extension.

Remove the ability to cause an input file to be deleted based on a filename specification.

Improve the safety of delegates.mgk by removing gnuplot support, removing manual page support, and by adding -dSAFER to all ghostscript invocations.

Sanity check the MVG image primitive filename argument to assure that 'magick:' prefix strings will not be interpreted. Please note that this patch will break intentional uses of magick prefix strings in MVG and so some MVG scripts may fail. We will search for a more flexible solution.

In addition the following issues have been fixed:

CVE-2015-8808

Assure that GIF decoder does not use unitialized data and cause an out-of-bound read.

CVE-2016-2317 and CVE-2016-2318 Vulnerabilities that allow to read or write outside memory bounds (heap, stack) as well as some null-pointer derreferences to cause a denial of service when parsing SVG files.

For Debian 7 Wheezy, these problems have been fixed in version 1.3.16-1.1+deb7u1.

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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.16-1.1+deb7u1", rls:"DEB7"))) {
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
