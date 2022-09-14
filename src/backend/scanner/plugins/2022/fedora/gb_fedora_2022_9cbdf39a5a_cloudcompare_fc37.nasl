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
  script_oid("1.3.6.1.4.1.25623.1.0.822431");
  script_version("2022-09-13T08:08:03+0000");
  script_cve_id("CVE-2021-21897");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-13 08:08:03 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 01:13:39 +0000 (Tue, 13 Sep 2022)");
  script_name("Fedora: Security Advisory for cloudcompare (FEDORA-2022-9cbdf39a5a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-9cbdf39a5a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/L2H36XRMAPQBIOVIIFX6KUT5YOG2ETM6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cloudcompare'
  package(s) announced via the FEDORA-2022-9cbdf39a5a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CloudCompare is a 3D point cloud (and triangular mesh) processing software.
It has been originally designed to perform comparison between two 3D points
clouds (such as the ones obtained with a laser scanner) or between a point
cloud and a triangular mesh.
It relies on a specific octree structure that enables great performances in
this particular function. It was also meant to deal with huge point clouds
(typically more than 10 millions points, and up to 120 millions with 2 Gb of
memory).

Afterwards, it has been extended to a more generic point cloud processing
software, including many advanced algorithms (registration, resampling,
color/normal/scalar fields handling, statistics computation, sensor
management, interactive or automatic segmentation, display enhancement...).");

  script_tag(name:"affected", value:"'cloudcompare' package(s) on Fedora 37.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"cloudcompare", rpm:"cloudcompare~2.11.3~4.fc37", rls:"FC37"))) {
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