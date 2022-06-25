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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0281");
  script_cve_id("CVE-2017-1000099", "CVE-2017-1000100", "CVE-2017-1000101");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-01 19:23:00 +0000 (Wed, 01 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0281");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0281.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21481");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20170809A.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20170809B.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20170809C.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2017-0281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When asking to get a file from a file:// URL, libcurl provides a feature that
outputs meta-data about the file using HTTP-like headers. The code doing this
would send the wrong buffer to the user (stdout or the application's provide
callback), which could lead to other private data from the heap to get
inadvertently displayed. The wrong buffer was an uninitialized memory area
allocated on the heap and if it turned out to not contain any zero byte, it
would continue and display the data following that buffer in memory
(CVE-2017-1000099).

When doing a TFTP transfer and curl/libcurl is given a URL that contains a very
long file name (longer than about 515 bytes), the file name is truncated to fit
within the buffer boundaries, but the buffer size is still wrongly updated to
use the untruncated length. This too large value is then used in the sendto()
call, making curl attempt to send more data than what is actually put into the
buffer. The sendto() function will then read beyond the end of the heap based
buffer. A malicious HTTP(S) server could redirect a vulnerable libcurl-using
client to a crafted TFTP URL (if the client hasn't restricted which protocols
it allows redirects to) and trick it to send private memory contents to a
remote server over UDP. Limit curl's redirect protocols with --proto-redir and
libcurl's with CURLOPT_REDIR_PROTOCOLS (CVE-2017-1000100).

curl supports 'globbing' of URLs, in which a user can pass a numerical range to
have the tool iterate over those numbers to do a sequence of transfers. In the
globbing function that parses the numerical range, there was an omission that
made curl read a byte beyond the end of the URL if given a carefully crafted,
or just wrongly written, URL. The URL is stored in a heap based buffer, so it
could then be made to wrongly read something else instead of crashing
(CVE-2017-1000101).");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.54.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.54.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.54.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.54.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.54.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.54.1~2.2.mga6", rls:"MAGEIA6"))) {
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
