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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0220");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2018-0220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0220");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0220.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22960");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/342ZTGQCOLK4EMJYROXHMDXITBWJISIU/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1564252");
  script_xref(name:"URL", value:"https://svn.boost.org/trac10/ticket/13036");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boost' package(s) announced via the MGASA-2018-0220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A new, potential integer overflow security issue was discovered in
Boost.Regex.
This update uses a patch from Boost that fixes this potential issue.");

  script_tag(name:"affected", value:"'boost' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"boost", rpm:"boost~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-bjam", rpm:"boost-bjam~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-build", rpm:"boost-build~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-devel-doc", rpm:"boost-devel-doc~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-doctools", rpm:"boost-doctools~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-examples", rpm:"boost-examples~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-devel", rpm:"lib64boost-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-graph-mpi1.60.0", rpm:"lib64boost-graph-mpi1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-graph-mpich1.60.0", rpm:"lib64boost-graph-mpich1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-mpi-python1.60.0", rpm:"lib64boost-mpi-python1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-mpich-devel", rpm:"lib64boost-mpich-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-mpich-python1.60.0", rpm:"lib64boost-mpich-python1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-mpich1.60.0", rpm:"lib64boost-mpich1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-openmpi-devel", rpm:"lib64boost-openmpi-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-openmpi1.60.0", rpm:"lib64boost-openmpi1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-python3_1.60.0", rpm:"lib64boost-python3_1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost-static-devel", rpm:"lib64boost-static-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_atomic1.60.0", rpm:"lib64boost_atomic1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_chrono1.60.0", rpm:"lib64boost_chrono1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_container1.60.0", rpm:"lib64boost_container1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_context1.60.0", rpm:"lib64boost_context1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_coroutine1.60.0", rpm:"lib64boost_coroutine1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_date_time1.60.0", rpm:"lib64boost_date_time1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_filesystem1.60.0", rpm:"lib64boost_filesystem1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_graph1.60.0", rpm:"lib64boost_graph1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_iostreams1.60.0", rpm:"lib64boost_iostreams1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_locale1.60.0", rpm:"lib64boost_locale1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_log1.60.0", rpm:"lib64boost_log1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_math1.60.0", rpm:"lib64boost_math1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_prg_exec_monitor1.60.0", rpm:"lib64boost_prg_exec_monitor1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_program_options1.60.0", rpm:"lib64boost_program_options1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_python1.60.0", rpm:"lib64boost_python1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_random1.60.0", rpm:"lib64boost_random1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_regex1.60.0", rpm:"lib64boost_regex1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_serialization1.60.0", rpm:"lib64boost_serialization1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_signals1.60.0", rpm:"lib64boost_signals1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_system1.60.0", rpm:"lib64boost_system1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_thread1.60.0", rpm:"lib64boost_thread1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_timer1.60.0", rpm:"lib64boost_timer1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_type_erasure1.60.0", rpm:"lib64boost_type_erasure1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_unit_test_framework1.60.0", rpm:"lib64boost_unit_test_framework1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_wave1.60.0", rpm:"lib64boost_wave1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64boost_wserialization1.60.0", rpm:"lib64boost_wserialization1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-devel", rpm:"libboost-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-graph-mpi1.60.0", rpm:"libboost-graph-mpi1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-graph-mpich1.60.0", rpm:"libboost-graph-mpich1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-mpi-python1.60.0", rpm:"libboost-mpi-python1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-mpich-devel", rpm:"libboost-mpich-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-mpich-python1.60.0", rpm:"libboost-mpich-python1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-mpich1.60.0", rpm:"libboost-mpich1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-openmpi-devel", rpm:"libboost-openmpi-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-openmpi1.60.0", rpm:"libboost-openmpi1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-python3_1.60.0", rpm:"libboost-python3_1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost-static-devel", rpm:"libboost-static-devel~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_atomic1.60.0", rpm:"libboost_atomic1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_chrono1.60.0", rpm:"libboost_chrono1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_container1.60.0", rpm:"libboost_container1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_context1.60.0", rpm:"libboost_context1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_coroutine1.60.0", rpm:"libboost_coroutine1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_date_time1.60.0", rpm:"libboost_date_time1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_filesystem1.60.0", rpm:"libboost_filesystem1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_graph1.60.0", rpm:"libboost_graph1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_iostreams1.60.0", rpm:"libboost_iostreams1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_locale1.60.0", rpm:"libboost_locale1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_log1.60.0", rpm:"libboost_log1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_math1.60.0", rpm:"libboost_math1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_prg_exec_monitor1.60.0", rpm:"libboost_prg_exec_monitor1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1.60.0", rpm:"libboost_program_options1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_python1.60.0", rpm:"libboost_python1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_random1.60.0", rpm:"libboost_random1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1.60.0", rpm:"libboost_regex1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_serialization1.60.0", rpm:"libboost_serialization1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1.60.0", rpm:"libboost_signals1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_system1.60.0", rpm:"libboost_system1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_thread1.60.0", rpm:"libboost_thread1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_timer1.60.0", rpm:"libboost_timer1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_type_erasure1.60.0", rpm:"libboost_type_erasure1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_unit_test_framework1.60.0", rpm:"libboost_unit_test_framework1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wave1.60.0", rpm:"libboost_wave1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_wserialization1.60.0", rpm:"libboost_wserialization1.60.0~1.60.0~6.1.mga6", rls:"MAGEIA6"))) {
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
