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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1025");
  script_version("2020-01-23T10:38:42+0000");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 10:38:42 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:38:42 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for squid (EulerOS-SA-2016-1025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1025");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'squid' package(s) announced via the EulerOS-SA-2016-1025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow flaw was found in the way the Squid cachemgr.cgi utility processed remotely relayed Squid input. When the CGI interface utility is used, a remote attacker could possibly use this flaw to execute arbitrary code. (CVE-2016-4051)

Buffer overflow and input validation flaws were found in the way Squid processed ESI responses. If Squid was used as a reverse proxy, or for TLS/HTTPS interception, a remote attacker able to control ESI components on an HTTP server could use these flaws to crash Squid, disclose parts of the stack memory, or possibly execute arbitrary code as the user running Squid. (CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

An input validation flaw was found in the way Squid handled intercepted HTTP Request messages. An attacker could use this flaw to bypass the protection against issues related to CVE-2009-0801, and perform cache poisoning attacks on Squid. (CVE-2016-4553)

An input validation flaw was found in Squid's mime_get_header_field() function, which is used to search for headers within HTTP requests. An attacker could send an HTTP request from the client side with specially crafted header Host header that bypasses same-origin security protections, causing Squid operating as interception or reverse-proxy to contact the wrong origin server. It could also be used for cache poisoning for client not following RFC 7230. (CVE-2016-4554)

A NULL pointer dereference flaw was found in the way Squid processes ESI responses. If Squid was used as a reverse proxy or for TLS/HTTPS interception, a malicious server could use this flaw to crash the Squid worker process. (CVE-2016-4555)

An incorrect reference counting flaw was found in the way Squid processes ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS interception, an attacker controlling a server accessed by Squid, could crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)");

  script_tag(name:"affected", value:"'squid' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.3.8~26.4", rls:"EULEROS-2.0SP1"))) {
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