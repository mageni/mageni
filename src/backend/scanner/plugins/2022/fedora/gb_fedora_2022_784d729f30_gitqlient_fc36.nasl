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
  script_oid("1.3.6.1.4.1.25623.1.0.822611");
  script_version("2022-10-14T08:45:30+0000");
  script_cve_id("CVE-2022-21680", "CVE-2022-21681");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-10-14 08:45:30 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-24 19:31:00 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-10-10 01:11:58 +0000 (Mon, 10 Oct 2022)");
  script_name("Fedora: Security Advisory for gitqlient (FEDORA-2022-784d729f30)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-784d729f30");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AIXDMC3CSHYW3YWVSQOXAWLUYQHAO5UX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gitqlient'
  package(s) announced via the FEDORA-2022-784d729f30 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GitQlient, pronounced as git+client (/gtklant/) is a multi-platform Git
client originally forked from QGit. Nowadays it goes beyond of just a fork and
adds a lot of new functionality.

Some of the major feature you can find are:

  * Easy access to remote actions like: push, pull, submodules management and
    branches

  * Branches management

  * Tags and stashes management

  * Submodules handling

  * Allow to open several repositories in the same window

  * Better visualization of the commits and the work in progress

  * Better visualization of the repository view

  * GitHub/GitLab integration

  * Embedded text editor with syntax highlight for C++");

  script_tag(name:"affected", value:"'gitqlient' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"gitqlient", rpm:"gitqlient~1.5.0~2.fc36", rls:"FC36"))) {
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