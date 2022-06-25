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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0423");
  script_cve_id("CVE-2018-0500", "CVE-2018-1000120", "CVE-2018-1000121", "CVE-2018-1000122", "CVE-2018-1000300", "CVE-2018-1000301", "CVE-2018-14618");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0423)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0423");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0423.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22772");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2018-9cd6.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2018-97a2.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2018-b047.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2018-82c2.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2018-b138.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2018-70a2.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/CVE-2018-14618.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3598-1/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/DOHQJ7DDUE5U4L6FHSUVPFQ7TAZLWSMI/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3710-1/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4286");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2018-0423 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated curl packages fix security vulnerabilities:

Peter Wu discovered that curl incorrectly handled certain SMTP buffers. A
remote attacker could use this issue to cause curl to crash, resulting in
a denial of service, or possibly execute arbitrary code (CVE-2018-0500).

Zhaoyang Wu discovered that cURL, an URL transfer library, contains a buffer
overflow in the NTLM authentication code triggered by passwords that exceed
2GB in length on 32bit systems (CVE-2018-14618).

Phan Thanh discovered that curl incorrectly handled certain FTP paths.
An attacker could use this to cause a denial of service or possibly
execute arbitrary code (CVE-2018-1000120).

Dario Weisser discovered that curl incorrectly handled certain LDAP URLs.
An attacker could possibly use this issue to cause a denial of service
(CVE-2018-1000121).

Max Dymond discovered that curl incorrectly handled certain RTSP data. An
attacker could possibly use this to cause a denial of service or even to
get access to sensitive data (CVE-2018-1000122).

A heap-based buffer overflow can happen when closing down an FTP connection
with very long server command replies. When doing FTP transfers, curl keeps
a spare 'closure handle' around internally that will be used when an FTP
connection gets shut down since the original curl easy handle is then
already removed. FTP server response data that gets cached from the original
transfer might then be larger than the default buffer size (16 KB) allocated
in the 'closure handle', which can lead to a buffer overwrite. The contents
and size of that overwrite is controllable by the server (CVE-2018-1000300).

curl can be tricked into reading data beyond the end of a heap based buffer
used to store downloaded content. When servers send RTSP responses back to
curl, the data starts out with a set of headers. curl parses that data to
separate it into a number of headers to deal with those appropriately and to
find the end of the headers that signal the start of the 'body' part. The
function that splits up the response into headers is called
'Curl_http_readwrite_headers()' and in situations where it can't find a
single header in the buffer, it might end up leaving a pointer pointing
into the buffer instead of to the start of the buffer which then later on
may lead to an out of buffer read when code assumes that pointer points to
a full buffer size worth of memory to use. This could potentially lead to
information leakage but most likely a crash/denial of service for
applications if a server triggers this flaw (CVE-2018-1000301).");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.54.1~2.7.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.54.1~2.7.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.54.1~2.7.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.54.1~2.7.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.54.1~2.7.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.54.1~2.7.mga6", rls:"MAGEIA6"))) {
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
