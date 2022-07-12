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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0335");
  script_cve_id("CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0335)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0335");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0335.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21664");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump, tcpdump' package(s) announced via the MGASA-2017-0335 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Summary for 4.9.2 tcpdump release

Do not use getprotobynumber() for protocol name resolution.
Do not do any protocol name resolution if -n is specified.
Improve errors detection in the test scripts.
Fix a segfault with OpenSSL 1.1 and improve OpenSSL usage.
Clean up IS-IS printing.

Fix buffer overflow vulnerabilities: CVE-2017-11543 (SLIP),
CVE-2017-13011 (bittok2str_internal)

Fix infinite loop vulnerabilities: CVE-2017-12989 (RESP), CVE-2017-12990
(ISAKMP), CVE-2017-12995 (DNS), CVE-2017-12997 (LLDP).

Fix buffer over-read vulnerabilities: CVE-2017-11541 (safeputs),
CVE-2017-11542 (PIMv1), CVE-2017-12893 (SMB/CIFS), CVE-2017-12894
(lookup_bytestring), CVE-2017-12895 (ICMP), CVE-2017-12896 (ISAKMP),
CVE-2017-12897 (ISO CLNS), CVE-2017-12898 (NFS), CVE-2017-12899 (DECnet),
CVE-2017-12900 (tok2strbuf), CVE-2017-12901 (EIGRP), CVE-2017-12902
(Zephyr), CVE-2017-12985 (IPv6), CVE-2017-12986 (IPv6 routing headers),
CVE-2017-12987 (IEEE 802.11), CVE-2017-12988 (telnet), CVE-2017-12991
(BGP), CVE-2017-12992 (RIPng), CVE-2017-12993 (Juniper), CVE-2017-11542
(PIMv1), CVE-2017-11541 (safeputs), CVE-2017-12994 (BGP), CVE-2017-12996
(PIMv2), CVE-2017-12998 (ISO IS-IS), CVE-2017-12999 (ISO IS-IS),
CVE-2017-13000 (IEEE 802.15.4), CVE-2017-13001 (NFS), CVE-2017-13002
(AODV), CVE-2017-13003 (LMP), CVE-2017-13004 (Juniper), CVE-2017-13005
(NFS), CVE-2017-13006 (L2TP), CVE-2017-13007 (Apple PKTAP),
CVE-2017-13008 (IEEE 802.11), CVE-2017-13009 (IPv6 mobility),
CVE-2017-13010 (BEEP), CVE-2017-13012 (ICMP), CVE-2017-13013 (ARP),
CVE-2017-13014 (White Board), CVE-2017-13015 (EAP), CVE-2017-11543
(SLIP), CVE-2017-13016 (ISO ES-IS), CVE-2017-13017 (DHCPv6),
CVE-2017-13018 (PGM), CVE-2017-13019 (PGM), CVE-2017-13020 (VTP),
CVE-2017-13021 (ICMPv6), CVE-2017-13022 (IP), CVE-2017-13023
(IPv6 mobility), CVE-2017-13024 (IPv6 mobility), CVE-2017-13025
(IPv6 mobility), CVE-2017-13026 (ISO IS-IS), CVE-2017-13027 (LLDP),
CVE-2017-13028 (BOOTP), CVE-2017-13029 (PPP), CVE-2017-13030 (PIM),
CVE-2017-13031 (IPv6 fragmentation header), CVE-2017-13032 (RADIUS),
CVE-2017-13033 (VTP), CVE-2017-13034 (PGM), CVE-2017-13035 (ISO IS-IS),
CVE-2017-13036 (OSPFv3), CVE-2017-13037 (IP), CVE-2017-13038 (PPP),
CVE-2017-13039 (ISAKMP), CVE-2017-13040 (MPTCP), CVE-2017-13041 (ICMPv6),
CVE-2017-13042 (HNCP), CVE-2017-13043 (BGP), CVE-2017-13044 (HNCP),
CVE-2017-13045 (VQP), CVE-2017-13046 (BGP), CVE-2017-13047 (ISO ES-IS),
CVE-2017-13048 (RSVP), CVE-2017-13049 (Rx), CVE-2017-13050 (RPKI-Router),
CVE-2017-13051 (RSVP), CVE-2017-13052 (CFM), CVE-2017-13053 (BGP),
CVE-2017-13054 (LLDP), CVE-2017-13055 (ISO IS-IS), CVE-2017-13687
(Cisco HDLC), CVE-2017-13688 (OLSR), CVE-2017-13689 (IKEv1),
CVE-2017-13690 (IKEv2), CVE-2017-13725 (IPv6 routing headers)");

  script_tag(name:"affected", value:"'tcpdump, tcpdump' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~1.mga6", rls:"MAGEIA6"))) {
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
