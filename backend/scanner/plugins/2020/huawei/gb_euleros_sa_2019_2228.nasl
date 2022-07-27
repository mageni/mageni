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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2228");
  script_version("2020-01-23T12:42:00+0000");
  script_cve_id("CVE-2016-1245", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:42:00 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:42:00 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for quagga (EulerOS-SA-2019-2228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2228");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'quagga' package(s) announced via the EulerOS-SA-2019-2228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the zebra daemon in Quagga before 1.0.20161017 suffered from a stack-based buffer overflow when processing IPv6 Neighbor Discovery messages. The root cause was relying on BUFSIZ to be compatible with a message size, however, BUFSIZ is system-dependent.(CVE-2016-1245)

The Quagga BGP daemon (bgpd) prior to version 1.2.3 can overrun internal BGP code-to-string conversion tables used for debug by 1 pointer value, based on input.(CVE-2018-5380)

The Quagga BGP daemon (bgpd) prior to version 1.2.3 has a bug in its parsing of 'Capabilities' in BGP OPEN messages, in the bgp_packet.c:bgp_capability_msg_parse function. The parser can enter an infinite loop on invalid capabilities if a Multi-Protocol capability does not have a recognized AFI/SAFI, causing a denial of service.(CVE-2018-5381)");

  script_tag(name:"affected", value:"'quagga' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.22.4~5.h6.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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