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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1128.1");
  script_tag(name:"creation_date", value:"2022-04-08 09:16:41 +0000 (Fri, 08 Apr 2022)");
  script_version("2022-04-12T08:08:23+0000");
  script_tag(name:"last_modification", value:"2022-04-12 10:03:57 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1128-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221128-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsolv, libzypp' package(s) announced via the SUSE-SU-2022:1128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsolv, libzypp fixes the following issues:

libsolv to 0.6.39:

fix memory leaks in SWIG generated code

fix misparsing of '&' in attributes with libxml2

try to keep packages from a cycle close together in the transaction order
 (bsc#1189622)

fix split provides not working if the update includes a forbidden vendor
 change (bsc#1195485)

fix segfault on conflict resolution when using bindings

do not replace noarch problem rules with arch dependent ones in problem
 reporting

fix and simplify pool_vendor2mask implementation

bump version to 0.6.39

libzypp to 16.22.4:

Hint on ptf resolver conflicts (bsc#1194848)

Fix package signature check (bsc#1184501) Pay attention that header and
 payload are secured by a valid signature and report more detailed which
 signature is missing.

Set ZYPP_RPM_DEBUG=1 to capture verbose rpm command output.");

  script_tag(name:"affected", value:"'libsolv, libzypp' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libsolv-debugsource", rpm:"libsolv-debugsource~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolv-tools-debuginfo", rpm:"libsolv-tools-debuginfo~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.22.4~27.85.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~16.22.4~27.85.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~16.22.4~27.85.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~16.22.4~27.85.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-solv-debuginfo", rpm:"perl-solv-debuginfo~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-solv-debuginfo", rpm:"python-solv-debuginfo~0.6.39~2.27.32.2", rls:"SLES12.0SP2"))) {
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
