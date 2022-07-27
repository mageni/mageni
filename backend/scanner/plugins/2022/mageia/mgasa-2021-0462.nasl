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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0462");
  script_cve_id("CVE-2019-20790", "CVE-2020-12272", "CVE-2020-12460");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-31 04:15:00 +0000 (Mon, 31 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0462");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0462.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29035");
  script_xref(name:"URL", value:"https://github.com/trusteddomainproject/OpenDMARC/issues/111");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opendmarc' package(s) announced via the MGASA-2021-0462 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenDMARC through 1.3.2 and 1.4.x, when used with pypolicyd-spf 2.0.2, allows
attacks that bypass SPF and DMARC authentication in situations where the HELO
field is inconsistent with the MAIL FROM field (CVE-2019-20790).

OpenDMARC through 1.3.2 and 1.4.x allows attacks that inject authentication
results to provide false information about the domain that originated an e-mail
message. This is caused by incorrect parsing and interpretation of SPF/DKIM
authentication results, as demonstrated by the example.net(.example.com
substring (CVE-2020-12272).

OpenDMARC through 1.3.2 and 1.4.x through 1.4.0-Beta1 has improper null
termination in the function opendmarc_xml_parse that can result in a one-byte
heap overflow in opendmarc_xml when parsing a specially crafted DMARC aggregate
report. This can cause remote memory corruption when a '\0' byte overwrites the
heap metadata of the next chunk and its PREV_INUSE flag (CVE-2020-12460).");

  script_tag(name:"affected", value:"'opendmarc' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64opendmarc-devel", rpm:"lib64opendmarc-devel~1.4.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opendmarc2", rpm:"lib64opendmarc2~1.4.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopendmarc-devel", rpm:"libopendmarc-devel~1.4.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopendmarc2", rpm:"libopendmarc2~1.4.1.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opendmarc", rpm:"opendmarc~1.4.1.1~1.mga8", rls:"MAGEIA8"))) {
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
