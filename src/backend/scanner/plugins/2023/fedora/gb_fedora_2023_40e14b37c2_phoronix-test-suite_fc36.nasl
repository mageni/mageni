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
  script_oid("1.3.6.1.4.1.25623.1.0.823125");
  script_version("2023-01-13T10:21:10+0000");
  script_cve_id("CVE-2022-40704");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-13 10:21:10 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-12 02:01:50 +0000 (Thu, 12 Jan 2023)");
  script_name("Fedora: Security Advisory for phoronix-test-suite (FEDORA-2023-40e14b37c2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-40e14b37c2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ETFF53AECMDP6PTNUVVCOODN3HMOETUU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phoronix-test-suite'
  package(s) announced via the FEDORA-2023-40e14b37c2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Phoronix Test Suite is the most comprehensive testing and benchmarking
platform available for the Linux operating system. This software is designed to
effectively carry out both qualitative and quantitative benchmarks in a clean,
reproducible, and easy-to-use manner. The Phoronix Test Suite consists of a
lightweight processing core (pts-core) with each benchmark consisting of an
XML-based profile with related resource scripts. The process from the benchmark
installation, to the actual benchmarking, to the parsing of important hardware
and software components is heavily automated and completely repeatable, asking
users only for confirmation of actions.");

  script_tag(name:"affected", value:"'phoronix-test-suite' package(s) on Fedora 36.");

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

  if(!isnull(res = isrpmvuln(pkg:"phoronix-test-suite", rpm:"phoronix-test-suite~10.8.4~2.fc36", rls:"FC36"))) {
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