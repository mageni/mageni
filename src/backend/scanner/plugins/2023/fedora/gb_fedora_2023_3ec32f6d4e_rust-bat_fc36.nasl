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
  script_oid("1.3.6.1.4.1.25623.1.0.827015");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-24765", "CVE-2022-29187");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-23 02:10:00 +0000 (Sat, 23 Apr 2022)");
  script_tag(name:"creation_date", value:"2023-01-31 02:03:44 +0000 (Tue, 31 Jan 2023)");
  script_name("Fedora: Security Advisory for rust-bat (FEDORA-2023-3ec32f6d4e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-3ec32f6d4e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UDZRZAL7QULOB6V7MKT66MOMWJLBJPX4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-bat'
  package(s) announced via the FEDORA-2023-3ec32f6d4e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cat(1) clone with wings.");

  script_tag(name:"affected", value:"'rust-bat' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"rust-bat", rpm:"rust-bat~0.21.0~6.fc36", rls:"FC36"))) {
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