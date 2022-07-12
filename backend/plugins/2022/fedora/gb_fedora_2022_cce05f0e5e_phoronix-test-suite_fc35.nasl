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
  script_oid("1.3.6.1.4.1.25623.1.0.820254");
  script_version("2022-04-14T11:53:12+0000");
  script_cve_id("CVE-2022-0571");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:53:12 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 21:24:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-04-05 01:04:47 +0000 (Tue, 05 Apr 2022)");
  script_name("Fedora: Security Advisory for phoronix-test-suite (FEDORA-2022-cce05f0e5e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-cce05f0e5e");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QO32MBF3FS65K5YIC6CHXAJTLLPAXJED");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phoronix-test-suite'
  package(s) announced via the FEDORA-2022-cce05f0e5e advisory.");

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

  script_tag(name:"affected", value:"'phoronix-test-suite' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"phoronix-test-suite", rpm:"phoronix-test-suite~10.8.2~1.fc35", rls:"FC35"))) {
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