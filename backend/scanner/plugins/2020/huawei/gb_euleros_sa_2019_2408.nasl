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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2408");
  script_version("2020-01-23T12:53:45+0000");
  script_cve_id("CVE-2016-1245", "CVE-2016-2342", "CVE-2016-4049", "CVE-2017-3224", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:53:45 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:53:45 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for quagga (EulerOS-SA-2019-2408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2408");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'quagga' package(s) announced via the EulerOS-SA-2019-2408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Open Shortest Path First (OSPF) protocol implementations may improperly determine Link State Advertisement (LSA) recency for LSAs with MaxSequenceNumber. According to RFC 2328 section 13.1, for two instances of the same LSA, recency is determined by first comparing sequence numbers, then checksums, and finally MaxAge. In a case where the sequence numbers are the same, the LSA with the larger checksum is considered more recent, and will not be flushed from the Link State Database (LSDB). Since the RFC does not explicitly state that the values of links carried by a LSA must be the same when prematurely aging a self-originating LSA with MaxSequenceNumber, it is possible in vulnerable OSPF implementations for an attacker to craft a LSA with MaxSequenceNumber and invalid links that will result in a larger checksum and thus a 'newer' LSA that will not be flushed from the LSDB. Propagation of the crafted LSA can result in the erasure or alteration of the routing tables of routers within the routing domain, creating a denial of service condition or the re-routing of traffic on the network. CVE-2017-3224 has been reserved for Quagga and downstream implementations (SUSE, openSUSE, and Red Hat packages).(CVE-2017-3224)

The bgp_dump_routes_func function in bgpd/bgp_dump.c in Quagga does not perform size checks when dumping data, which might allow remote attackers to cause a denial of service (assertion failure and daemon crash) via a large BGP packet.(CVE-2016-4049)

The bgp_nlri_parse_vpnv4 function in bgp_mplsvpn.c in the VPNv4 NLRI parser in bgpd in Quagga before 1.0.20160309, when a certain VPNv4 configuration is used, relies on a Labeled-VPN SAFI routes-data length field during a data copy, which allows remote attackers to execute arbitrary code or cause a denial of service (stack-based buffer overflow) via a crafted packet.(CVE-2016-2342)

The Quagga BGP daemon (bgpd) prior to version 1.2.3 can overrun internal BGP code-to-string conversion tables used for debug by 1 pointer value, based on input.(CVE-2018-5380)

The Quagga BGP daemon (bgpd) prior to version 1.2.3 has a bug in its parsing of 'Capabilities' in BGP OPEN messages, in the bgp_packet.c:bgp_capability_msg_parse function. The parser can enter an infinite loop on invalid capabilities if a Multi-Protocol capability does not have a recognized AFI/SAFI, causing a denial of service.(CVE-2018-5381)

It was discovered that the zebra daemon in Quagga before 1.0.20161017 suffered from a stack-based buffer overflow when processing IPv6 Neighbor Discovery messages. The root cause was relying on BUFSIZ to be compatible with a message size, however, BUFSIZ is system-dependent.(CVE-2016-1245)");

  script_tag(name:"affected", value:"'quagga' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.22.4~5.h6", rls:"EULEROS-2.0SP2"))) {
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