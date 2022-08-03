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
  script_oid("1.3.6.1.4.1.25623.1.0.821915");
  script_version("2022-08-02T12:00:10+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-02 12:00:10 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-07-31 01:15:22 +0000 (Sun, 31 Jul 2022)");
  script_name("Fedora: Security Advisory for golang-github-hashicorp-memdb (FEDORA-2022-ea8f4e232d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-ea8f4e232d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VANPYT7O7BQN5IMA6JGPKXQ4CFYUZPOM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-hashicorp-memdb'
  package(s) announced via the FEDORA-2022-ea8f4e232d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Memdb package implements a simple in-memory database built on immutable
radix trees. The database provides Atomicity, Consistency and Isolation from
ACID. Being that it is in-memory, it does not provide durability. The database
is instantiated with a schema that specifies the tables and indices that exist
and allows transactions to be executed.

The database provides the following:

  - Multi-Version Concurrency Control (MVCC) - By leveraging immutable radix
   trees the database is able to support any number of concurrent readers
   without locking, and allows a writer to make progress.

  - Transaction Support - The database allows for rich transactions, in which
   multiple objects are inserted, updated or deleted. The transactions can span
   multiple tables, and are applied atomically. The database provides atomicity
   and isolation in ACID terminology, such that until commit the updates are not
   visible.

  - Rich Indexing - Tables can support any number of indexes, which can be simple
   like a single field index, or more advanced compound field indexes. Certain
   types like UUID can be efficiently compressed from strings into byte indexes
   for reduced storage requirements.

  - Watches - Callers can populate a watch set as part of a query, which can be
   used to detect when a modification has been made to the database which
   affects the query results. This lets callers easily watch for changes in the
   database in a very general way.");

  script_tag(name:"affected", value:"'golang-github-hashicorp-memdb' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-hashicorp-memdb", rpm:"golang-github-hashicorp-memdb~1.3.0~6.fc36", rls:"FC36"))) {
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