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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0094");
  script_cve_id("CVE-2018-17580", "CVE-2018-17582", "CVE-2018-17974", "CVE-2018-18407", "CVE-2018-18408");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 16:41:00 +0000 (Fri, 29 Mar 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0094)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0094");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0094.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24148");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/5UTDLO275Z67H3IN6UL57U6OAI4R3G5I/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpreplay' package(s) announced via the MGASA-2019-0094 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Tcpreplay 4.3.0 beta1. A heap-based buffer
over-read was triggered in the function dlt_en10mb_encode() of the file
plugins/dlt_en10mb/en10mb.c, due to inappropriate values in the function
memmove(). The length (pktlen + ctx -> l2len) can be larger than source
value (packet + ctx->l2len) because the function fails to ensure the length
of a packet is valid. This leads to Denial of Service. (CVE-2018-17974)

A heap-based buffer over-read exists in the function fast_edit_packet() in
the file send_packets.c of Tcpreplay v4.3.0 beta1. This can lead to Denial
of Service (DoS) and potentially Information Exposure when the application
attempts to process a crafted pcap file. (CVE-2018-17580)

Tcpreplay v4.3.0 beta1 contains a heap-based buffer over-read. The
get_next_packet() function in the send_packets.c file uses the memcpy()
function unsafely to copy sequences from the source buffer pktdata to the
destination (*prev_packet)->pktdata. This will result in a Denial of
Service (DoS) and potentially Information Exposure when the application
attempts to process a file. (CVE-2018-17582)

A heap-based buffer over-read was discovered in the tcpreplay-edit binary
of Tcpreplay 4.3.0 beta1, during the incremental checksum operation. The
issue gets triggered in the function csum_replace4() in
incremental_checksum.h, causing a denial of service. (CVE-2018-18407)

A use-after-free was discovered in the tcpbridge binary of Tcpreplay 4.3.0
beta1. The issue gets triggered in the function post_args() at tcpbridge.c,
causing a denial of service or possibly unspecified other impact.
(CVE-2018-18408)");

  script_tag(name:"affected", value:"'tcpreplay' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay", rpm:"tcpreplay~4.3.1~1.mga6", rls:"MAGEIA6"))) {
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
