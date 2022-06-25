# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1852");
  script_version("2021-05-03T06:23:42+0000");
  script_cve_id("CVE-2019-12523", "CVE-2019-12526", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18679", "CVE-2020-14058", "CVE-2020-25097");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-03 10:25:12 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-03 06:23:42 +0000 (Mon, 03 May 2021)");
  script_name("Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2021-1852)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1852");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1852");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'squid' package(s) announced via the EulerOS-SA-2021-1852 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Squid 2.x, 3.x, and 4.x through 4.8. Due to incorrect data management, it is vulnerable to information disclosure when processing HTTP Digest Authentication. Nonce tokens contain the raw byte value of a pointer that sits within heap memory allocation. This information reduces ASLR protections and may aid attackers isolating memory areas to target for remote code execution attacks.(CVE-2019-18679)

An issue was discovered in Squid 3.x and 4.x through 4.8 when the append_domain setting is used (because the appended characters do not properly interact with hostname length restrictions). Due to incorrect message processing, it can inappropriately redirect traffic to origins it should not be delivered to.(CVE-2019-18677)

An issue was discovered in Squid 3.x and 4.x through 4.8. Due to incorrect input validation, there is a heap-based buffer overflow that can result in Denial of Service to all clients using the proxy. Severity is high due to this vulnerability occurring before normal security checks, any remote client that can reach the proxy port can trivially perform the attack via a crafted URI scheme.(CVE-2019-18676)

An issue was discovered in Squid before 4.12 and 5.x before 5.0.3. Due to use of a potentially dangerous function, Squid and the default certificate validation helper are vulnerable to a Denial of Service when opening a TLS connection to an attacker-controlled server for HTTPS. This occurs because unrecognized error values are mapped to NULL, but later code expects that each error value is mapped to a valid error string.(CVE-2020-14058)

An issue was discovered in Squid before 4.9. URN response handling in Squid suffers from a heap-based buffer overflow. When receiving data from a remote server in response to an URN request, Squid fails to ensure that the response can fit within the buffer. This leads to attacker controlled data overflowing in the heap.(CVE-2019-12526)

An issue was discovered in Squid before 4.9. When handling a URN request, a corresponding HTTP request is made. This HTTP request doesn't go through the access checks that incoming HTTP requests go through. This causes all access checks to be bypassed and allows access to restricted HTTP servers, e.g., an attacker can connect to HTTP servers that only listen on localhost.(CVE-2019-12523)

An issue was discovered in Squid through 4.13 and 5.x through 5.0.4. Due to improper input validation, it allows a trusted client to perform HTTP Request Smuggling and access services otherwise forbidden by the security controls. This occurs for certain uri_whitespace configuration settings.(CVE-2020-25097)");

  script_tag(name:"affected", value:"'squid' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.5.20~2.2.h13", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-migration-script", rpm:"squid-migration-script~3.5.20~2.2.h13", rls:"EULEROS-2.0SP3"))) {
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