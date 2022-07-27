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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0053");
  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624", "CVE-2016-9586", "CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-1000254", "CVE-2017-1000257", "CVE-2017-7407", "CVE-2017-8816", "CVE-2017-8817");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0053");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0053.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19700");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102A.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102B.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102C.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102D.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102E.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102F.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102G.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102H.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102I.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102J.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161221A.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20170403.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20170809A.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20170809B.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20171004.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20171023.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2017-12e7.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_2017-ae72.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2018-0053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"If cookie state is written into a cookie jar file that is later read back and
used for subsequent requests, a malicious HTTP server can inject new cookies
for arbitrary domains into said cookie jar. The issue pertains to the function
that loads cookies into memory, which reads the specified file into a
fixed-size buffer in a line-by-line manner using the fgets() function. If an
invocation of fgets() cannot read the whole line into the destination buffer
due to it being too small, it truncates the output. This way, a very long
cookie (name + value) sent by a malicious server would be stored in the file
and subsequently that cookie could be read partially and crafted correctly, it
could be treated as a different cookie for another server (CVE-2016-8615).

When re-using a connection, curl was doing case insensitive comparisons of
user name and password with the existing connections. This means that if an
unused connection with proper credentials exists for a protocol that has
connection-scoped credentials, an attacker can cause that connection to be
reused if s/he knows the case-insensitive version of the correct password
(CVE-2016-8616).

In libcurl's base64 encode function, the output buffer is allocated without
any checks on a variable used to determine its size. On systems with 32-bit
addresses in userspace, the multiplication in the expression wraps around if
the size is too large. If this happens, an undersized output buffer will be
allocated, but the full result will be written, thus causing the memory behind
the output buffer to be overwritten. If a username is set directly via
CURLOPT_USERNAME (or curl's -u, --user option), this vulnerability can be
triggered. The name has to be at least 512MB big in a 32bit system. Systems
with 64 bit versions of the size_t type are not affected by this issue
(CVE-2016-8617).

The libcurl API function called curl_maprintf() can be tricked into doing a
double-free due to an unsafe size_t multiplication, on systems using 32 bit
size_t variables. The function is also used internallty in numerous
situations. The function doubles an allocated memory area with realloc() and
allows the size to wrap and become zero and when doing so realloc() returns
NULL and frees the memory - in contrary to normal realloc() fails where it
only returns NULL - causing libcurl to free the memory again in the error
path. Systems with 64 bit versions of the size_t type are not affected by this
issue. This behavior is triggable using the publicly exposed function
(CVE-2016-8618).

In curl's implementation of the Kerberos authentication mechanism, the
function read_data() in security.c is used to fill the necessary krb5
structures. When reading one of the length fields from the socket, it fails to
ensure that the length parameter passed to realloc() is not set to 0. This
would lead to realloc() getting called with a zero size and when doing so
realloc() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.40.0~3.14.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.40.0~3.14.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.40.0~3.14.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.40.0~3.14.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.40.0~3.14.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.40.0~3.14.mga5", rls:"MAGEIA5"))) {
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
