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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0195");
  script_cve_id("CVE-2016-0764");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-01 14:13:00 +0000 (Wed, 01 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0195");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0195.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18125");
  script_xref(name:"URL", value:"https://mail.gnome.org/archives/networkmanager-list/2016-April/msg00000.html");
  script_xref(name:"URL", value:"https://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/NEWS?h=1.0.12");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181143.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'networkmanager' package(s) announced via the MGASA-2016-0195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated networkmanager package fixes security vulnerability:

NetworkManager before 1.0.12 is vulnerable to a race condition that could lead
to a local information leak (CVE-2016-0764).

The networkmanager package has been updated to version 1.0.12, which fixes this
issue and several other bugs. See the upstream NEWS file for details.");

  script_tag(name:"affected", value:"'networkmanager' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64networkmanager-gir1.0", rpm:"lib64networkmanager-gir1.0~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-devel", rpm:"lib64nm-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib-devel", rpm:"lib64nm-glib-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib-vpn-devel", rpm:"lib64nm-glib-vpn-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib-vpn1", rpm:"lib64nm-glib-vpn1~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-glib4", rpm:"lib64nm-glib4~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-util-devel", rpm:"lib64nm-util-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm-util2", rpm:"lib64nm-util2~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nm0", rpm:"lib64nm0~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nmclient-gir1.0", rpm:"lib64nmclient-gir1.0~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetworkmanager-gir1.0", rpm:"libnetworkmanager-gir1.0~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-devel", rpm:"libnm-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib-devel", rpm:"libnm-glib-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib-vpn-devel", rpm:"libnm-glib-vpn-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib-vpn1", rpm:"libnm-glib-vpn1~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-glib4", rpm:"libnm-glib4~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-util-devel", rpm:"libnm-util-devel~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm-util2", rpm:"libnm-util2~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnm0", rpm:"libnm0~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnmclient-gir1.0", rpm:"libnmclient-gir1.0~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager", rpm:"networkmanager~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"networkmanager-tui", rpm:"networkmanager-tui~1.0.12~1.1.mga5", rls:"MAGEIA5"))) {
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
