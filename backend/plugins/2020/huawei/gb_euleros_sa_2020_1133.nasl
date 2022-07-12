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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1133");
  script_version("2020-02-24T09:07:23+0000");
  script_cve_id("CVE-2019-12523", "CVE-2019-12526", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-25 11:00:29 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-24 09:07:23 +0000 (Mon, 24 Feb 2020)");
  script_name("Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2020-1133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1133");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'squid' package(s) announced via the EulerOS-SA-2020-1133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Squid 2.x, 3.x, and 4.x through 4.8. Due to incorrect data management, it is vulnerable to information disclosure when processing HTTP Digest Authentication. Nonce tokens contain the raw byte value of a pointer that sits within heap memory allocation. This information reduces ASLR protections and may aid attackers isolating memory areas to target for remote code execution attacks.(CVE-2019-18679)

An issue was discovered in Squid 3.x and 4.x through 4.8 when the append_domain setting is used (because the appended characters do not properly interact with hostname length restrictions). Due to incorrect message processing, it can inappropriately redirect traffic to origins it should not be delivered to.(CVE-2019-18677)

An issue was discovered in Squid 3.x and 4.x through 4.8. Due to incorrect input validation, there is a heap-based buffer overflow that can result in Denial of Service to all clients using the proxy. Severity is high due to this vulnerability occurring before normal security checks, any remote client that can reach the proxy port can trivially perform the attack via a crafted URI scheme.(CVE-2019-18676)

An issue was discovered in Squid 3.x and 4.x through 4.8. It allows attackers to smuggle HTTP requests through frontend software to a Squid instance that splits the HTTP Request pipeline differently. The resulting Response messages corrupt caches (between a client and Squid) with attacker-controlled content at arbitrary URLs. Effects are isolated to software between the attacker client and Squid. There are no effects on Squid itself, nor on any upstream servers. The issue is related to a request header containing whitespace between a header name and a colon.(CVE-2019-18678)

An issue was discovered in Squid before 4.9. URN response handling in Squid suffers from a heap-based buffer overflow. When receiving data from a remote server in response to an URN request, Squid fails to ensure that the response can fit within the buffer. This leads to attacker controlled data overflowing in the heap.(CVE-2019-12526)

An issue was discovered in Squid before 4.9. When handling a URN request, a corresponding HTTP request is made. This HTTP request doesn't go through the access checks that incoming HTTP requests go through. This causes all access checks to be bypassed and allows access to restricted HTTP servers, e.g., an attacker can connect to HTTP servers that only listen on localhost.(CVE-2019-12523)");

  script_tag(name:"affected", value:"'squid' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.8~3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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