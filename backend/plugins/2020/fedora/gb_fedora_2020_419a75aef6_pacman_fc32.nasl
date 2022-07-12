# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877738");
  script_version("2020-04-30T08:51:29+0000");
  script_cve_id("CVE-2019-18182", "CVE-2019-18183");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-30 08:51:29 +0000 (Thu, 30 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-30 03:14:51 +0000 (Thu, 30 Apr 2020)");
  script_name("Fedora: Security Advisory for pacman (FEDORA-2020-419a75aef6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KIDJ4XKBZRRVRFFGKUA3ZU6NFIP5JUG3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacman'
  package(s) announced via the FEDORA-2020-419a75aef6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pacman is the package manager used by the Arch distribution. It can
be used to install Arch into a container or to recover an Arch
installation from a Fedora system (see arch-install-scripts package
for instructions).

Pacman is a frontend for the ALPM (Arch Linux Package Management)
library Pacman does not strive to 'do everything.' It will add, remove
and upgrade packages in the system, and it will allow you to query the
package database for installed packages, files and owners. It also
attempts to handle dependencies automatically and can download
packages from a remote server. Arch packages are simple archives, with
.pkg.tar.gz extension for binary packages and .src.tar.gz for source
packages.");

  script_tag(name:"affected", value:"'pacman' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"pacman", rpm:"pacman~5.2.1~2.fc32", rls:"FC32"))) {
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
