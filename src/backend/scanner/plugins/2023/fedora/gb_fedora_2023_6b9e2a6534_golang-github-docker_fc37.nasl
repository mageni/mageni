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
  script_oid("1.3.6.1.4.1.25623.1.0.823130");
  script_version("2023-01-13T10:21:10+0000");
  script_cve_id("CVE-2022-39379");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-13 10:21:10 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 02:01:27 +0000 (Wed, 11 Jan 2023)");
  script_name("Fedora: Security Advisory for golang-github-docker (FEDORA-2023-6b9e2a6534)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6b9e2a6534");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LUT4QNBCOYSZDVQ6PHFLREXTTVI7KQQ5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-docker'
  package(s) announced via the FEDORA-2023-6b9e2a6534 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moby is an open-source project created by Docker to enable and accelerate
software containerization.

It provides a 'Lego set' of toolkit components, the framework for assembling
them into custom container-based systems, and a place for all container
enthusiasts and professionals to experiment and exchange ideas. Components
include container build tools, a container registry, orchestration tools, a
runtime and more, and these can be used as building blocks in conjunction with
other tools and projects.");

  script_tag(name:"affected", value:"'golang-github-docker' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker", rpm:"golang-github-docker~22.06.0~beta.0", rls:"FC37"))) {
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
