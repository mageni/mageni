# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2049");
  script_version("2020-09-29T14:06:08+0000");
  script_cve_id("CVE-2019-16785", "CVE-2019-16786", "CVE-2019-16789");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-09-29 14:06:08 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 13:42:06 +0000 (Tue, 29 Sep 2020)");
  script_name("Huawei EulerOS: Security Advisory for python-waitress (EulerOS-SA-2020-2049)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.6\.0");

  script_xref(name:"EulerOS-SA", value:"2020-2049");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2049");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'python-waitress' package(s) announced via the EulerOS-SA-2020-2049 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Waitress through version 1.3.1 would parse the Transfer-Encoding header and only look for a single string value, if that value was not chunked it would fall through and use the Content-Length header instead. According to the HTTP standard Transfer-Encoding should be a comma separated list, with the inner-most encoding first, followed by any further transfer codings, ending with chunked. Requests sent with: 'Transfer-Encoding: gzip, chunked' would incorrectly get ignored, and the request would use a Content-Length header instead to determine the body size of the HTTP message. This could allow for Waitress to treat a single request as multiple requests in the case of HTTP pipelining. This issue is fixed in Waitress 1.4.0.(CVE-2019-16786)

Waitress through version 1.3.1 implemented a 'MAY' part of the RFC7230 which states: 'Although the line terminator for the start-line and header fields is the sequence CRLF, a recipient MAY recognize a single LF as a line terminator and ignore any preceding CR.' Unfortunately if a front-end server does not parse header fields with an LF the same way as it does those with a CRLF it can lead to the front-end and the back-end server parsing the same HTTP message in two different ways. This can lead to a potential for HTTP request smuggling/splitting whereby Waitress may see two requests while the front-end server only sees a single HTTP message. This issue is fixed in Waitress 1.4.0.(CVE-2019-16785)

In Waitress through version 1.4.0, if a proxy server is used in front of waitress, an invalid request may be sent by an attacker that bypasses the front-end and is parsed differently by waitress leading to a potential for HTTP request smuggling. Specially crafted requests containing special whitespace characters in the Transfer-Encoding header would get parsed by Waitress as being a chunked request, but a front-end server would use the Content-Length instead as the Transfer-Encoding header is considered invalid due to containing invalid characters. If a front-end server does HTTP pipelining to a backend Waitress server this could lead to HTTP request splitting which may lead to potential cache poisoning or unexpected information disclosure. This issue is fixed in Waitress 1.4.1 through more strict HTTP field validation.(CVE-2019-16789)");

  script_tag(name:"affected", value:"'python-waitress' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"python2-waitress", rpm:"python2-waitress~1.1.0~6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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