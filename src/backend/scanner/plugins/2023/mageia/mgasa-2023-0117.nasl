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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0117");
  script_cve_id("CVE-2020-3299", "CVE-2020-3315", "CVE-2021-1223", "CVE-2021-1224", "CVE-2021-1236", "CVE-2021-1494", "CVE-2021-1495", "CVE-2021-34749", "CVE-2021-40114");
  script_tag(name:"creation_date", value:"2023-03-31 04:15:06 +0000 (Fri, 31 Mar 2023)");
  script_version("2023-03-31T10:08:37+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:37 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-29 13:15:00 +0000 (Fri, 29 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2023-0117)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0117");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0117.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27741");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3317");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snort' package(s) announced via the MGASA-2023-0117 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Cisco products are affected by a vulnerability in the Snort
detection engine that could allow an unauthenticated, remote attacker to
bypass a configured File Policy for HTTP. The vulnerability is due to
incorrect detection of modified HTTP packets used in chunked responses. An
attacker could exploit this vulnerability by sending crafted HTTP packets
through an affected device. A successful exploit could allow the attacker
to bypass a configured File Policy for HTTP packets and deliver a
malicious payload. (CVE-2020-3299)

Multiple Cisco products are affected by a vulnerability in the Snort
detection engine that could allow an unauthenticated, remote attacker to
bypass the configured file policies on an affected system. The
vulnerability is due to errors in how the Snort detection engine handles
specific HTTP responses. An attacker could exploit this vulnerability by
sending crafted HTTP packets that would flow through an affected system. A
successful exploit could allow the attacker to bypass the configured file
policies and deliver a malicious payload to the protected network.
(CVE-2020-3315)

Multiple Cisco products are affected by a vulnerability in the Snort
detection engine that could allow an unauthenticated, remote attacker to
bypass a configured file policy for HTTP. The vulnerability is due to
incorrect handling of an HTTP range header. An attacker could exploit this
vulnerability by sending crafted HTTP packets through an affected device.
A successful exploit could allow the attacker to bypass configured file
policy for HTTP packets and deliver a malicious payload. (CVE-2021-1223)

Multiple Cisco products are affected by a vulnerability with TCP Fast Open
(TFO) when used in conjunction with the Snort detection engine that could
allow an unauthenticated, remote attacker to bypass a configured file
policy for HTTP. The vulnerability is due to incorrect detection of the
HTTP payload if it is contained at least partially within the TFO
connection handshake. An attacker could exploit this vulnerability by
sending crafted TFO packets with an HTTP payload through an affected
device. A successful exploit could allow the attacker to bypass
configured file policy for HTTP packets and deliver a malicious payload.
(CVE-2021-1224)

Multiple Cisco products are affected by a vulnerability in the Snort
application detection engine that could allow an unauthenticated, remote
attacker to bypass the configured policies on an affected system. The
vulnerability is due to a flaw in the detection algorithm. An attacker
could exploit this vulnerability by sending crafted packets that would
flow through an affected system. A successful exploit could allow the
attacker to bypass the configured policies and deliver a malicious
payload to the protected network. (CVE-2021-1236)

Multiple Cisco products are affected by vulnerabilities in the Snort
detection engine that could allow ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'snort' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"snort", rpm:"snort~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-bloat", rpm:"snort-bloat~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-devel", rpm:"snort-devel~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-inline+flexresp", rpm:"snort-inline+flexresp~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-inline", rpm:"snort-inline~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-mysql+flexresp", rpm:"snort-mysql+flexresp~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-mysql", rpm:"snort-mysql~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-plain+flexresp", rpm:"snort-plain+flexresp~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-postgresql+flexresp", rpm:"snort-postgresql+flexresp~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-postgresql", rpm:"snort-postgresql~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-prelude+flexresp", rpm:"snort-prelude+flexresp~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snort-prelude", rpm:"snort-prelude~2.9.20~1.mga8", rls:"MAGEIA8"))) {
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
