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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1423");
  script_version("2020-01-23T11:44:32+0000");
  script_cve_id("CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:44:32 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:44:32 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for dnsmasq (EulerOS-SA-2019-1423)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1423");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'dnsmasq' package(s) announced via the EulerOS-SA-2019-1423 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap buffer overflow was discovered in dnsmasq in the IPv6 router advertisement (RA) handling code. An attacker on the local network segment could send crafted RAs to dnsmasq which would cause it to crash or, potentially, execute arbitrary code. This issue only affected configurations using one of these options: enable-ra, ra-only, slaac, ra-names, ra-advrouter, or ra-stateless.(CVE-2017-14492)

An information leak was found in dnsmasq in the DHCPv6 relay code. An attacker on the local network could send crafted DHCPv6 packets to dnsmasq causing it to forward the contents of process memory, potentially leaking sensitive data.(CVE-2017-14494)

A heap buffer overflow was found in dnsmasq in the code responsible for building DNS replies. An attacker could send crafted DNS packets to dnsmasq which would cause it to crash or, potentially, execute arbitrary code.(CVE-2017-14491)

A memory exhaustion flaw was found in dnsmasq in the EDNS0 code. An attacker could send crafted DNS packets which would trigger memory allocations which would never be freed, leading to unbounded memory consumption and eventually a crash. This issue only affected configurations using one of the options: add-mac, add-cpe-id, or add-subnet.(CVE-2017-14495)

An integer underflow flaw leading to a buffer over-read was found in dnsmasq in the EDNS0 code. An attacker could send crafted DNS packets to dnsmasq which would cause it to crash. This issue only affected configurations using one of the options: add-mac, add-cpe-id, or add-subnet.(CVE-2017-14496)

A stack buffer overflow was found in dnsmasq in the DHCPv6 code. An attacker on the local network could send a crafted DHCPv6 request to dnsmasq which would cause it to a crash or, potentially, execute arbitrary code.(CVE-2017-14493)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.76~5.h2", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.76~5.h2", rls:"EULEROSVIRT-3.0.1.0"))) {
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