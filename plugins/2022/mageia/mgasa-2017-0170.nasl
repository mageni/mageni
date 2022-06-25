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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0170");
  script_cve_id("CVE-2016-10324", "CVE-2016-10325", "CVE-2016-10326", "CVE-2017-7853");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0170");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0170.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20758");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-04/msg00109.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exosip, libosip2, siproxd' package(s) announced via the MGASA-2017-0170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libosip2 in GNU oSIP 4.1.0, a malformed SIP message can lead to a
heap buffer overflow in the osip_clrncpy() function defined in
osipparser2/osip_port.c (CVE-2016-10324).

In libosip2 in GNU oSIP 4.1.0, a malformed SIP message can lead to a
heap buffer overflow in the _osip_message_to_str() function defined in
osipparser2/osip_message_to_str.c, resulting in a remote DoS
(CVE-2016-10325).

In libosip2 in GNU oSIP 4.1.0, a malformed SIP message can lead to a
heap buffer overflow in the osip_body_to_str() function defined in
osipparser2/osip_body.c, resulting in a remote DoS (CVE-2016-10326).

In libosip2 in GNU 5.0.0, a malformed SIP message can lead to a heap
buffer overflow in the msg_osip_body_parse() function defined in
osipparser2/osip_message_parse.c, resulting in a remote DoS
(CVE-2017-7853).");

  script_tag(name:"affected", value:"'exosip, libosip2, siproxd' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"exosip", rpm:"exosip~4.0.0~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exosip2-devel", rpm:"lib64exosip2-devel~4.0.0~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exosip2_10", rpm:"lib64exosip2_10~4.0.0~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osip2-devel", rpm:"lib64osip2-devel~5.0.0~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64osip2_12", rpm:"lib64osip2_12~5.0.0~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexosip2-devel", rpm:"libexosip2-devel~4.0.0~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexosip2_10", rpm:"libexosip2_10~4.0.0~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosip2", rpm:"libosip2~5.0.0~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosip2-devel", rpm:"libosip2-devel~5.0.0~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libosip2_12", rpm:"libosip2_12~5.0.0~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"siproxd", rpm:"siproxd~0.8.1~14.3.mga5", rls:"MAGEIA5"))) {
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
