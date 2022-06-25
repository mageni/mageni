# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.819399");
  script_version("2021-12-09T09:30:06+0000");
  script_cve_id("CVE-2021-41160");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-09 11:40:32 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 16:35:00 +0000 (Thu, 04 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-12-04 02:25:09 +0000 (Sat, 04 Dec 2021)");
  script_name("Fedora: Security Advisory for medusa (FEDORA-2021-ac23d9e47f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-ac23d9e47f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KV6YMJEPENSQIJ22O4RQNS5MC6IKGK5O");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'medusa'
  package(s) announced via the FEDORA-2021-ac23d9e47f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Medusa is a speedy, massively parallel, modular,
login brute-forcer for network services.
Some of the key features of Medusa are:

  * Thread-based parallel testing. Brute-force
      testing can be performed against multiple hosts,
      users or passwords concurrently.

  * Flexible user input. Target information
      (host/user/password) can be specified in a variety of ways.
      For example, each item can be either a single
      entry or a file containing multiple entries.
      Additionally, a combination file format allows
      the user to refine their target listing.

  * Modular design. Each service module exists
      as an independent .mod file.
      This means that no modifications are necessary
      to the core application in order to extend
      the supported list of services for brute-forcing.");

  script_tag(name:"affected", value:"'medusa' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"medusa", rpm:"medusa~2.2~14.20181216git292193b.fc33", rls:"FC33"))) {
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