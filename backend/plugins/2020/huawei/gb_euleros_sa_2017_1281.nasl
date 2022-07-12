# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1281");
  script_version("2020-01-23T15:42:05+0000");
  script_cve_id("CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12897", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 15:42:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:04:12 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for tcpdump (EulerOS-SA-2017-1281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1281");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'tcpdump' package(s) announced via the EulerOS-SA-2017-1281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The RSVP parser in tcpdump before 4.9.2 has a buffer over-read in print-rsvp.c:rsvp_obj_print().(CVE-2017-13048)

The ARP parser in tcpdump before 4.9.2 has a buffer over-read in print-arp.c, several functions.(CVE-2017-13013)

The VTP parser in tcpdump before 4.9.2 has a buffer over-read in print-vtp.c:vtp_print().(CVE-2017-13033)

The OSPFv3 parser in tcpdump before 4.9.2 has a buffer over-read in print-ospf6.c:ospf6_decode_v3().(CVE-2017-13036)

The ISO ES-IS parser in tcpdump before 4.9.2 has a buffer over-read in print-isoclns.c:esis_print().(CVE-2017-13047)

The IPv6 mobility parser in tcpdump before 4.9.2 has a buffer over-read in print-mobility.c:mobility_opt_print().(CVE-2017-13025)

The PGM parser in tcpdump before 4.9.2 has a buffer over-read in print-pgm.c:pgm_print().(CVE-2017-13019)

The IPv6 parser in tcpdump before 4.9.2 has a buffer over-read in print-ip6.c:ip6_print().(CVE-2017-12985)

The IPv6 routing header parser in tcpdump before 4.9.2 has a buffer over-read in print-rt6.c:rt6_print().(CVE-2017-13725)

The telnet parser in tcpdump before 4.9.2 has a buffer over-read in print-telnet.c:telnet_parse().(CVE-2017-12988)

The BGP parser in tcpdump before 4.9.2 has a buffer over-read in print-bgp.c:bgp_attr_print().(CVE-2017-12991)

The MPTCP parser in tcpdump before 4.9.2 has a buffer over-read in print-mptcp.c, several functions.(CVE-2017-13040)

The PPP parser in tcpdump before 4.9.2 has a buffer over-read in print-ppp.c:print_ccp_config_options().(CVE-2017-13029)

The IEEE 802.15.4 parser in tcpdump before 4.9.2 has a buffer over-read in print-802_15_4.c:ieee802_15_4_if_print().(CVE-2017-13000)

The IP parser in tcpdump before 4.9.2 has a buffer over-read in print-ip.c:ip_printroute().(CVE-2017-13022)

The ISAKMP parser in tcpdump before 4.9.2 has a buffer over-read in print-isakmp.c, several functions.(CVE-2017-13039)

The IPv6 fragmentation header parser in tcpdump before 4.9.2 has a buffer over-read in print-frag6.c:frag6_print().(CVE-2017-13031)

The PIM parser in tcpdump before 4.9.2 has a buffer over-read in print-pim.c, several functions.(CVE-2017-13030)

The BGP parser in tcpdump before 4.9.2 has a buffer over-read in print-bgp.c:bgp_attr_print().(CVE-2017-12994)

The BGP parser in tcpdump before 4.9.2 has a buffer over-read in print-bgp.c:decode_multicast_vpn().(CVE-2017-13043)

The VQP parser in tcpdump before 4.9.2 has a buffer over-read in print-vqp.c:vqp_print().(CVE-2017-13045)

The LLDP parser in tcpdump before 4.9.2 has a buffer over-read in print-lldp.c:lldp_private_8023_print().(CVE-2017-13054, CVE-2017-12998, CVE-2017-13014, CVE-2017-13037, CVE-2017-13690 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.0~5.h175", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);