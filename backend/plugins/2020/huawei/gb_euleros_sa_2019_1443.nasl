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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1443");
  script_version("2020-01-23T11:47:10+0000");
  script_cve_id("CVE-2015-8605", "CVE-2016-2774", "CVE-2017-3144", "CVE-2018-5732", "CVE-2018-5733");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:47:10 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:47:10 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for dhcp (EulerOS-SA-2019-1443)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1443");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'dhcp' package(s) announced via the EulerOS-SA-2019-1443 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ISC DHCP 4.x before 4.1-ESV-R12-P1, 4.2.x, and 4.3.x before 4.3.3-P1 allows remote attackers to cause a denial of service (application crash) via an invalid length field in a UDP IPv4 packet.(CVE-2015-8605)

A denial of service flaw was found in the way dhcpd handled reference counting when processing client requests. A malicious DHCP client could use this flaw to trigger a reference count overflow on the server side, potentially causing dhcpd to crash, by sending large amounts of traffic.(CVE-2018-5733)

An out-of-bound memory access flaw was found in the way dhclient processed a DHCP response packet. A malicious DHCP server could potentially use this flaw to crash dhclient processes running on DHCP client machines via a crafted DHCP response packet.(CVE-2018-5732)

A resource-consumption flaw was discovered in the DHCP server. dhcpd did not restrict the number of open connections to OMAPI and failover ports. A remote attacker able to establish TCP connections to one of these ports could use this flaw to cause dhcpd to exit unexpectedly, stop responding requests, or exhaust system sockets (denial of service).(CVE-2016-2774)

It was found that the DHCP daemon did not properly clean up closed OMAPI connections in certain cases. A remote attacker able to connect to the OMAPI port could use this flaw to exhaust file descriptors in the DHCP daemon, leading to a denial of service in the OMAPI functionality.(CVE-2017-3144)");

  script_tag(name:"affected", value:"'dhcp' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"dhclient", rpm:"dhclient~4.2.5~68.1.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.2.5~68.1.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-common", rpm:"dhcp-common~4.2.5~68.1.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-libs", rpm:"dhcp-libs~4.2.5~68.1.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
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