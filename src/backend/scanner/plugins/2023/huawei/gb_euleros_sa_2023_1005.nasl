# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1005");
  script_cve_id("CVE-2022-32221", "CVE-2022-35252", "CVE-2022-42915", "CVE-2022-42916");
  script_tag(name:"creation_date", value:"2023-01-09 15:11:01 +0000 (Mon, 09 Jan 2023)");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-31 19:54:00 +0000 (Mon, 31 Oct 2022)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2023-1005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1005");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1005");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2023-1005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in curl. The issue occurs when doing HTTP(S) transfers, where curl might erroneously use the read callback (CURLOPT_READFUNCTION) to ask for data to send, even when the CURLOPT_POSTFIELDS option has been set if it previously used the same handle to issue a PUT request which used that callback. This flaw may surprise the application and cause it to misbehave and either send off the wrong data or use memory after free or similar in the subsequent POST request.(CVE-2022-32221)

In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step) even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.). The earliest affected version is 7.77.0 2021-05-26.(CVE-2022-42916)

curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200 status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap, ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0.(CVE-2022-42915)

 When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control codes that when later are sent back to a HTTPserver might make the server return 400 responses. Effectively allowing a'sister site' to deny service to all siblings.(CVE-2022-35252)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.79.1~2.h8.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.79.1~2.h8.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
