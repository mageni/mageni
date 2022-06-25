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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0061");
  script_cve_id("CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0061");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0061.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20212");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3775");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/01/30/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpcap, tcpdump' package(s) announced via the MGASA-2017-0061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The AH parser in tcpdump before 4.9.0 has a buffer overflow in
print-ah.c:ah_print(). (CVE-2016-7922)

The ARP parser in tcpdump before 4.9.0 has a buffer overflow in
print-arp.c:arp_print(). (CVE-2016-7923)

The ATM parser in tcpdump before 4.9.0 has a buffer overflow in
print-atm.c:oam_print(). (CVE-2016-7924)

The compressed SLIP parser in tcpdump before 4.9.0 has a buffer overflow
in print-sl.c:sl_if_print(). (CVE-2016-7925)

The Ethernet parser in tcpdump before 4.9.0 has a buffer overflow in
print-ether.c:ethertype_print(). (CVE-2016-7926)

The IEEE 802.11 parser in tcpdump before 4.9.0 has a buffer overflow in
print-802_11.c:ieee802_11_radio_print(). (CVE-2016-7927)

The IPComp parser in tcpdump before 4.9.0 has a buffer overflow in
print-ipcomp.c:ipcomp_print(). (CVE-2016-7928)

The Juniper PPPoE ATM parser in tcpdump before 4.9.0 has a buffer overflow
in print-juniper.c:juniper_parse_header(). (CVE-2016-7929)

The LLC/SNAP parser in tcpdump before 4.9.0 has a buffer overflow in
print-llc.c:llc_print(). (CVE-2016-7930)

The MPLS parser in tcpdump before 4.9.0 has a buffer overflow in
print-mpls.c:mpls_print(). (CVE-2016-7931)

The PIM parser in tcpdump before 4.9.0 has a buffer overflow in
print-pim.c:pimv2_check_checksum(). (CVE-2016-7932)

The PPP parser in tcpdump before 4.9.0 has a buffer overflow in
print-ppp.c:ppp_hdlc_if_print(). (CVE-2016-7933)

The RTCP parser in tcpdump before 4.9.0 has a buffer overflow in
print-udp.c:rtcp_print(). (CVE-2016-7934)

The RTP parser in tcpdump before 4.9.0 has a buffer overflow in
print-udp.c:rtp_print(). (CVE-2016-7935)

The UDP parser in tcpdump before 4.9.0 has a buffer overflow in
print-udp.c:udp_print(). (CVE-2016-7936)

The VAT parser in tcpdump before 4.9.0 has a buffer overflow in
print-udp.c:vat_print(). (CVE-2016-7937)

The ZeroMQ parser in tcpdump before 4.9.0 has an integer overflow in
print-zeromq.c:zmtp1_print_frame(). (CVE-2016-7938)

The GRE parser in tcpdump before 4.9.0 has a buffer overflow in
print-gre.c, multiple functions. (CVE-2016-7939)

The STP parser in tcpdump before 4.9.0 has a buffer overflow in
print-stp.c, multiple functions. (CVE-2016-7940)

The AppleTalk parser in tcpdump before 4.9.0 has a buffer overflow in
print-atalk.c, multiple functions. (CVE-2016-7973)

The IP parser in tcpdump before 4.9.0 has a buffer overflow in
print-ip.c, multiple functions. (CVE-2016-7974)

The TCP parser in tcpdump before 4.9.0 has a buffer overflow in
print-tcp.c:tcp_print(). (CVE-2016-7975)

The BOOTP parser in tcpdump before 4.9.0 has buffer overflows in
print-bootp.c:bootp_print(). (CVE-2016-7983 and CVE-2017-5203)

The TFTP parser in tcpdump before 4.9.0 has a buffer overflow in
print-tftp.c:tftp_print(). (CVE-2016-7984)

The CALM FAST parser in tcpdump before 4.9.0 has a buffer overflow in
print-calm-fast.c:calm_fast_print(). (CVE-2016-7985)

The GeoNetworking parser in tcpdump before 4.9.0 has a buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libpcap, tcpdump' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pcap-devel", rpm:"lib64pcap-devel~1.8.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcap1", rpm:"lib64pcap1~1.8.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap", rpm:"libpcap~1.8.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap-devel", rpm:"libpcap-devel~1.8.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap-doc", rpm:"libpcap-doc~1.8.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcap1", rpm:"libpcap1~1.8.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.0~1.mga5", rls:"MAGEIA5"))) {
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
