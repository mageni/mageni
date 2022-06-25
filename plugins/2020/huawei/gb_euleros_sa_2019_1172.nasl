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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1172");
  script_version("2020-01-23T11:33:34+0000");
  script_cve_id("CVE-2013-4545", "CVE-2013-6422", "CVE-2014-0139", "CVE-2014-2522", "CVE-2017-7407", "CVE-2018-1000007");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-01-23 11:33:34 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:33:34 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2019-1172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1172");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'curl' package(s) announced via the EulerOS-SA-2019-1172 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cURL and libcurl 7.18.0 through 7.32.0, when built with OpenSSL, disables the certificate CN and SAN name field verification (CURLOPT_SSL_VERIFYHOST) when the digital signature verification (CURLOPT_SSL_VERIFYPEER) is disabled, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.CVE-2013-4545

The GnuTLS backend in libcurl 7.21.4 through 7.33.0, when disabling digital signature verification (CURLOPT_SSL_VERIFYPEER), also disables the CURLOPT_SSL_VERIFYHOST check for CN or SAN host name fields, which makes it easier for remote attackers to spoof servers and conduct man-in-the-middle (MITM) attacks.CVE-2013-6422

cURL and libcurl 7.1 before 7.36.0, when using the OpenSSL, axtls, qsossl or gskit libraries for TLS, recognize a wildcard IP address in the subject's Common Name (CN) field of an X.509 certificate, which might allow man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority.CVE-2014-0139

curl and libcurl 7.27.0 through 7.35.0, when running on Windows and using the SChannel/Winssl TLS backend, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate when accessing a URL that uses a numerical IP address, which allows man-in-the-middle attackers to spoof servers via an arbitrary valid certificate.CVE-2014-2522

The ourWriteOut function in tool_writeout.c in curl 7.53.1 might allow physically proximate attackers to obtain sensitive information from process memory in opportunistic circumstances by reading a workstation screen during use of a --write-out argument ending in a '%' character, which leads to a heap-based buffer over-read.CVE-2017-7407

It was found that curl and libcurl might send their Authentication header to a third party HTTP server upon receiving an HTTP REDIRECT reply. This could leak authentication token to external entities.CVE-2018-1000007");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization 2.5.3.");

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

if(release == "EULEROSVIRT-2.5.3") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~35.h24", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~35.h24", rls:"EULEROSVIRT-2.5.3"))) {
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