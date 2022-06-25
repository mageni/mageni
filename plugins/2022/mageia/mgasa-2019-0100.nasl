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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0100");
  script_cve_id("CVE-2018-10873", "CVE-2018-10893", "CVE-2019-3813");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0100)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0100");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0100.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24257");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/01/28/2");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:0231");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3870-1/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OWH2AHGKTPR5QUGXUYGY6CAEI3O7RPLL/");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/08/17/1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-09/msg00007.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-09/msg00010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice' package(s) announced via the MGASA-2019-0100 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Spice, versions 0.5.2 through 0.14.1, are vulnerable to an out-of-bounds
read due to an off-by-one error in memslot_get_virt. This may lead to a
denial of service, or, in the worst case, code-execution by unauthenticated
attackers. (CVE-2019-3813)

A vulnerability was discovered in SPICE before version 0.14.1 where the
generated code used for demarshalling messages lacked sufficient bounds
checks. A malicious client or server, after authentication, could send
specially crafted messages to its peer which would result in a crash or,
potentially, other impacts. (CVE-2018-10873)

Multiple integer overflow and buffer overflow issues were discovered in
spice-client's handling of LZ compressed frames. A malicious server could
cause the client to crash or, potentially, execute arbitrary code.
(CVE-2018-10893)");

  script_tag(name:"affected", value:"'spice' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-server-devel", rpm:"lib64spice-server-devel~0.13.90~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-server1", rpm:"lib64spice-server1~0.13.90~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-server-devel", rpm:"libspice-server-devel~0.13.90~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-server1", rpm:"libspice-server1~0.13.90~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice", rpm:"spice~0.13.90~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice-client", rpm:"spice-client~0.13.90~1.2.mga6", rls:"MAGEIA6"))) {
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
