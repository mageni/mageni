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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0500");
  script_cve_id("CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-07 18:57:00 +0000 (Thu, 07 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0500");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0500.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29527");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the MGASA-2021-0500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated docker packages fix security vulnerabilities:

A bug was found in Moby (Docker Engine) where attempting to copy files
using `docker cp` into a specially-crafted container can result in Unix
file permission changes for existing files in the hosts filesystem,
widening access to others. This bug does not directly allow files to be
read, modified, or executed without an additional cooperating process
(CVE-2021-41089).

A bug was found in Moby (Docker Engine) where the data directory (typically
'/var/lib/docker') contained subdirectories with insufficiently restricted
permissions, allowing otherwise unprivileged Linux users to traverse
directory contents and execute programs. When containers included executable
programs with extended permission bits (such as 'setuid'), unprivileged
Linux users could discover and execute those programs. When the UID of an
unprivileged Linux user on the host collided with the file owner or group
inside a container, the unprivileged Linux user on the host could discover,
read, and modify those files (CVE-2021-41091).

A bug was found in the Docker CLI where running 'docker login
my-private-registry.example.com' with a misconfigured configuration file
(typically '~/.docker/config.json') listing a 'credsStore' or 'credHelpers'
that could not be executed would result in any provided credentials being
sent to 'registry-1.docker.io' rather than the intended private registry
(CVE-2021-41092).");

  script_tag(name:"affected", value:"'docker' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.9~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~20.10.9~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.9~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-logrotate", rpm:"docker-logrotate~20.10.9~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-nano", rpm:"docker-nano~20.10.9~3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~20.10.9~3.mga8", rls:"MAGEIA8"))) {
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
