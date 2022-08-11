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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2128");
  script_cve_id("CVE-2022-22576", "CVE-2022-27774", "CVE-2022-27775", "CVE-2022-27776");
  script_tag(name:"creation_date", value:"2022-07-29 04:28:40 +0000 (Fri, 29 Jul 2022)");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 13:55:00 +0000 (Wed, 08 Jun 2022)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2022-2128)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2128");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2128");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2022-2128 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"curl follows HTTP(S) redirects when asked to. curl also supports authentication. When a user and password are provided for a URL with a given hostname, curl makes an effort to not pass on those credentials to other hosts in redirects unless given permission with a special option. This 'same host check' has been flawed all since it was introduced. It does not work on cross protocol redirects and it does not consider different port numbers to be separate hosts. This leads to curl leaking credentials to other servers when it follows redirects from auth protected HTTP(S) URLs to other protocols and port numbers. It could also leak the TLS SRP credentials this way. By default, curl only allows redirects to HTTP(S) and FTP(S), but can be asked to allow redirects to all protocols curl supports. We are not aware of any exploit of this flaw.(CVE-2022-27774)

A vulnerability was found in curl. This security flaw allows leak authentication or cookie header data on HTTP redirects to the same host but another port number. Sending the same set of headers to a server on a different port number is a problem for applications that pass on custom `Authorization:` or `Cookie:`headers. Those headers often contain privacy-sensitive information or data.(CVE-2022-27776)

A vulnerability was found in curl. This security flaw allows reusing OAUTH2-authenticated connections without properly ensuring that the connection was authenticated with the same credentials set for this transfer. This issue leads to an authentication bypass, either by mistake or by a malicious actor.(CVE-2022-22576)

libcurl keeps previously used connections in a connection pool for subsequent transfers to reuse, if one of them matches the setup. Due to errors in the logic, the config matching function did not take the IPv6 address zone id into account which could lead to libcurl reusing the wrong connection when one transfer uses a zone id and a subsequent transfer uses another (or no) zone id. We are not aware of any exploit of this flaw.(CVE-2022-27775)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.71.1~4.h13.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.71.1~4.h13.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
