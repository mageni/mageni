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
  script_oid("1.3.6.1.4.1.25623.1.0.827206");
  script_version("2023-03-01T10:09:26+0000");
  script_cve_id("CVE-2023-0778");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:09:26 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-26 02:03:31 +0000 (Sun, 26 Feb 2023)");
  script_name("Fedora: Security Advisory for podman (FEDORA-2023-998dbd3b79)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-998dbd3b79");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/433CLRBARZUJMR7U4DJ4JCLG2RS4U37K");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman'
  package(s) announced via the FEDORA-2023-998dbd3b79 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"podman (Pod Manager) is a fully featured container engine that is a simple
daemonless tool.  podman provides a Docker-CLI comparable command line that
eases the transition from other container engines and allows the management of
pods, containers and images.  Simply put: alias docker=podman.
Most podman commands can be run as a regular user, without requiring
additional privileges.

podman uses Buildah(1) internally to create container images.
Both tools share image (not container) storage, hence each can use or
manipulate images (but not containers) created by the other.

Manage Pods, Containers and Container Images
podman Simple management tool for pods, containers and images");

  script_tag(name:"affected", value:"'podman' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.4.1~3.fc36", rls:"FC36"))) {
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