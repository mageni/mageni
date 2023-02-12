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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4801.1");
  script_cve_id("CVE-2017-1000203");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4801-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4801-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4801-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'root-system' package(s) announced via the USN-4801-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ROOT incorrectly handled certain input arguments. An
attacker could possibly use this issue to execute arbitrary code.");

  script_tag(name:"affected", value:"'root-system' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libroot-bindings-python5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-bindings-ruby5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-core5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-geom5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf2d-gpad5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf2d-graf5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf2d-postscript5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf3d-eve5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf3d-g3d5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf3d-gl5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-gui-ged5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-gui5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-hist-spectrum5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-hist5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-html5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-io-xmlparser5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-io5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-foam5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-genvector5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-mathcore5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-mathmore5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-matrix5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-minuit5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-mlp5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-physics5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-quadp5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-smatrix5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-splot5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-unuran5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-misc-memstat5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-misc-minicern5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-misc-table5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-montecarlo-eg5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-montecarlo-vmc5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net-auth5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net-bonjour5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net-ldap5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-proof-proofplayer5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-proof5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-roofit5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-static", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-tmva5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-tree-treeplayer5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-tree5.34", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-geom-gdml", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-geom-geombuilder", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-geom-geompainter", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf2d-asimage", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf2d-x11", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf3d-x3d", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-fitpanel", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-guibuilder", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-sessionviewer", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-hist-hbook", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-hist-histpainter", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-hist-spectrumpainter", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-io-sql", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-io-xml", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-math-fftw3", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-math-fumili", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-math-minuit2", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-montecarlo-pythia8", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-net-globus", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-net-krb5", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-sql-mysql", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-sql-odbc", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-sql-pgsql", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-tree-treeviewer", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-bin", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-common", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-proofd", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-rootd", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-root-installer", ver:"5.34.14-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libroot-bindings-python5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-bindings-ruby5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-core5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-geom5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf2d-gpad5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf2d-graf5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf2d-postscript5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf3d-eve5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf3d-g3d5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-graf3d-gl5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-gui-ged5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-gui5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-hist-spectrum5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-hist5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-html5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-io-xmlparser5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-io5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-foam5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-genvector5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-mathcore5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-mathmore5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-matrix5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-minuit5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-mlp5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-physics5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-quadp5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-smatrix5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-splot5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-math-unuran5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-misc-memstat5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-misc-minicern5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-misc-table5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-montecarlo-eg5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-montecarlo-vmc5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net-auth5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net-bonjour5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net-ldap5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-net5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-proof-proofplayer5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-proof5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-roofit5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-static", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-tmva5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-tree-treeplayer5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroot-tree5.34", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-geom-gdml", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-geom-geombuilder", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-geom-geompainter", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf2d-asimage", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf2d-qt", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf2d-x11", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-graf3d-x3d", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-fitpanel", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-guibuilder", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-qt", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-gui-sessionviewer", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-hist-hbook", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-hist-histpainter", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-hist-spectrumpainter", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-io-sql", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-io-xml", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-math-fftw3", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-math-fumili", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-math-minuit2", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-montecarlo-pythia8", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-net-globus", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-net-krb5", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-sql-mysql", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-sql-odbc", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-sql-pgsql", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-plugin-tree-treeviewer", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-bin", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-common", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-proofd", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system-rootd", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"root-system", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-root-installer", ver:"5.34.30-0ubuntu8+esm1", rls:"UBUNTU16.04 LTS"))) {
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
