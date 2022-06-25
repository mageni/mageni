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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0153");
  script_cve_id("CVE-2019-9894", "CVE-2019-9895", "CVE-2019-9897", "CVE-2019-9898");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 05:29:00 +0000 (Fri, 05 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0153");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0153.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24547");
  script_xref(name:"URL", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/LDO3F267P347E6U2IILFCYW7JPTLCCES/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TBPZ6RAMBOJAKKPJ54MPIPJTXNB2T6FW/");
  script_xref(name:"URL", value:"https://trac.wxwidgets.org/ticket/17942");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla, libfilezilla, putty, wxgtk' package(s) announced via the MGASA-2019-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A remotely triggerable memory overwrite in RSA key exchange in PuTTY before
0.71 can occur before host key verification (CVE-2019-9894).

In PuTTY versions before 0.71 on Unix, a remotely triggerable buffer
overflow exists in any kind of server-to-client forwarding (CVE-2019-9895).

Multiple denial-of-service attacks that can be triggered by writing to the
terminal exist in PuTTY versions before 0.71 (CVE-2019-9897).

Potential recycling of random numbers used in cryptography exists within
PuTTY before 0.71 (CVE-2019-9898).

The putty package has been updated to version 0.71 and the filezilla package
has been updated and patched to fix these issues.

wxgtk has been updated to fix an assert when starting filezilla.");

  script_tag(name:"affected", value:"'filezilla, libfilezilla, putty, wxgtk' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.31.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla-devel", rpm:"lib64filezilla-devel~0.12.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla0", rpm:"lib64filezilla0~0.12.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wxgtku3.0-devel", rpm:"lib64wxgtku3.0-devel~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wxgtku3.0_0", rpm:"lib64wxgtku3.0_0~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wxgtkugl3.0_0", rpm:"lib64wxgtkugl3.0_0~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla", rpm:"libfilezilla~0.12.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-devel", rpm:"libfilezilla-devel~0.12.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla0", rpm:"libfilezilla0~0.12.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwxgtku3.0-devel", rpm:"libwxgtku3.0-devel~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwxgtku3.0_0", rpm:"libwxgtku3.0_0~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwxgtkugl3.0_0", rpm:"libwxgtkugl3.0_0~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.71~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wxgtk", rpm:"wxgtk~3.0.3.1~1.1.mga6", rls:"MAGEIA6"))) {
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
