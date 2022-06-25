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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1062");
  script_cve_id("CVE-2021-22876", "CVE-2021-22897", "CVE-2021-22898", "CVE-2021-22922", "CVE-2021-22923", "CVE-2021-22924", "CVE-2021-22925");
  script_tag(name:"creation_date", value:"2022-02-13 03:23:50 +0000 (Sun, 13 Feb 2022)");
  script_version("2022-02-13T03:23:50+0000");
  script_tag(name:"last_modification", value:"2022-02-15 11:09:28 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-02 09:15:00 +0000 (Thu, 02 Sep 2021)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2022-1062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1062");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1062");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2022-1062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized data from a stack based buffer to the server, resulting in potentially revealing sensitive internal information to the server using a clear-text network protocol.(CVE-2021-22898)

curl 7.61.0 through 7.76.1 suffers from exposure of data element to wrong session due to a mistake in the code for CURLOPT_SSL_CIPHER_LIST when libcurl is built to use the Schannel TLS library. The selected cipher set was stored in a single 'static' variable in the library, which has the surprising side-effect that if an application sets up multiple concurrent transfers, the last one that sets the ciphers will accidentally control the set used by all transfers. In a worst-case scenario, this weakens transport security significantly.(CVE-2021-22897)

curl 7.1.1 to and including 7.75.0 is vulnerable to an 'Exposure of Private Personal Information to an Unauthorized Actor' by leaking credentials in the HTTP Referer: header. libcurl does not strip off user credentials from the URL when automatically populating the Referer: HTTP request header field in outgoing HTTP requests, and therefore risks leaking sensitive data to the server that is the target of the second HTTP request.(CVE-2021-22876)

A flaw was found in libcurl in the way libcurl handles previously used connections without accounting for 'issuer cert' and comparing the involved paths case-insensitively. This flaw allows libcurl to use the wrong connection. The highest threat from this vulnerability is to confidentiality.(CVE-2021-22924)

A has been found in curl. The fix for CVE-2021-22898 doesn't remedy the vulnerability. A flaw in the option parser for sending NEW_ENV variables libcurl can pass uninitialized data from a stack-based buffer to the server. This issue leads to potentially revealing sensitive internal information to the server using a clear-text network protocol. The highest threat from this vulnerability is to confidentiality.(CVE-2021-22925)

A flaw was found in curl in the way curl handles a file hash mismatch after downloading content using the Metalink feature. This flaw allows malicious actors controlling a hosting server to trick users into downloading malicious content. The highest threat from this vulnerability is to integrity.(CVE-2021-22922)

A flaw was found in curl in the way curl handles credentials when downloading content using the Metalink feature. This flaw allows malicious actors controlling a hosting server to gain access to credentials provided while downloading content without the user's knowledge. The highest threat from this vulnerability is to confidentiality.(CVE-2021-22923)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.61.1~2.h16.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.61.1~2.h16.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.61.1~2.h16.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
