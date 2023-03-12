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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.1177");
  script_cve_id("CVE-2017-14975", "CVE-2017-14976", "CVE-2017-14977", "CVE-2017-15565");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-14 17:42:00 +0000 (Thu, 14 Mar 2019)");

  script_name("Debian: Security Advisory (DLA-1177)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1177");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1177");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'poppler' package(s) announced via the DLA-1177 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that poppler, a PDF rendering library, was affected by several denial-of-service (application crash), null pointer dereferences and heap-based buffer over-read bugs:

CVE-2017-14975

The FoFiType1C::convertToType0 function in FoFiType1C.cc has a NULL pointer dereference vulnerability because a data structure is not initialized, which allows an attacker to launch a denial of service attack.

CVE-2017-14976

The FoFiType1C::convertToType0 function in FoFiType1C.cc has a heap-based buffer over-read vulnerability if an out-of-bounds font dictionary index is encountered, which allows an attacker to launch a denial of service attack.

CVE-2017-14977

The FoFiTrueType::getCFFBlock function in FoFiTrueType.cc has a NULL pointer dereference vulnerability due to lack of validation of a table pointer, which allows an attacker to launch a denial of service attack.

CVE-2017-15565

NULL Pointer Dereference exists in the GfxImageColorMap::getGrayLine() function in GfxState.cc via a crafted PDF document.

For Debian 7 Wheezy, these problems have been fixed in version 0.18.4-6+deb7u4.

We recommend that you upgrade your poppler packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'poppler' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-poppler-0.18", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp-dev", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-cpp0", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-dev", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib-dev", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-glib8", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-private-dev", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-3", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler-qt4-dev", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler19", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-dbg", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.18.4-6+deb7u4", rls:"DEB7"))) {
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
