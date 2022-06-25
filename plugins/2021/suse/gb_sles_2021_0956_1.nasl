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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0956.1");
  script_cve_id("CVE-2017-9271");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-04-19T13:49:56+0000");
  script_tag(name:"last_modification", value:"2021-04-20 10:28:26 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-19 13:37:28 +0200 (Mon, 19 Apr 2021)");

  script_name("SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2021:0956-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-March/008560.html");

  script_tag(name:"summary", value:"The remote host is missing an update for 'libzypp, zypper'
  package(s) announced via the SUSE-SU-2021:0956-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"'libzypp, zypper' package(s) on SUSE Linux Enterprise Server 15");

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

if(release == "SLES15.0SP1") {
  if(!isnull(res = isrpmvuln(pkg:"libsigc", rpm:"libsigc~", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsigc-2_0-0", rpm:"libsigc-2_0-0~2.10.0~3.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsigc-2_0-0-debuginfo", rpm:"libsigc-2_0-0-debuginfo~2.10.0~3.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debuginfo", rpm:"libsolv-debuginfo~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debugsource", rpm:"libsolv-debugsource~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel-debuginfo", rpm:"libsolv-devel-debuginfo~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools-debuginfo", rpm:"libsolv-tools-debuginfo~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg-debugsource", rpm:"libyui-ncurses-pkg-debugsource~2.48.9~7.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg-devel", rpm:"libyui-ncurses-pkg-devel~2.48.9~7.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg9", rpm:"libyui-ncurses-pkg9~2.48.9~7.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg9-debuginfo", rpm:"libyui-ncurses-pkg9-debuginfo~2.48.9~7.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg-debugsource", rpm:"libyui-qt-pkg-debugsource~2.45.28~3.10.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg-devel", rpm:"libyui-qt-pkg-devel~2.45.28~3.10.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg9", rpm:"libyui-qt-pkg9~2.45.28~3.10.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg9-debuginfo", rpm:"libyui-qt-pkg9-debuginfo~2.45.28~3.10.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~17.25.8~3.48.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~17.25.8~3.48.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~17.25.8~3.48.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~17.25.8~3.48.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv-debuginfo", rpm:"perl-solv-debuginfo~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv", rpm:"python3-solv~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-solv-debuginfo", rpm:"python3-solv-debuginfo~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv", rpm:"ruby-solv~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-solv-debuginfo", rpm:"ruby-solv-debuginfo~0.7.17~3.32.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-pkg-bindings", rpm:"yast2-pkg-bindings~4.1.3~3.10.3", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-pkg-bindings-debuginfo", rpm:"yast2-pkg-bindings-debuginfo~4.1.3~3.10.3", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-pkg-bindings-debugsource", rpm:"yast2-pkg-bindings-debugsource~4.1.3~3.10.3", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.14.43~3.34.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debuginfo", rpm:"zypper-debuginfo~1.14.43~3.34.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-debugsource", rpm:"zypper-debugsource~1.14.43~3.34.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-ncurses-pkg-doc", rpm:"libyui-ncurses-pkg-doc~2.48.9~7.7.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyui-qt-pkg-doc", rpm:"libyui-qt-pkg-doc~2.45.28~3.10.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.14.43~3.34.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-needs-restarting", rpm:"zypper-needs-restarting~1.14.43~3.34.1", rls:"SLES15.0SP1"))){
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
