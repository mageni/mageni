# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0082.1");
  script_cve_id("CVE-2020-1971", "CVE-2020-8265", "CVE-2020-8287");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:46+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-19 18:13:00 +0000 (Fri, 19 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0082-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210082-1/");
  script_xref(name:"URL", value:"https://cwe.mitre.org/data/definitions/444.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2021:0082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs10 fixes the following issues:

New upstream LTS version 10.23.1:
 * CVE-2020-8265: use-after-free in TLSWrap (High) bug in TLS
 implementation. When writing to a TLS enabled socket,
 node::StreamBase::Write calls node::TLSWrap::DoWrite with a freshly
 allocated WriteWrap object as first argument. If the DoWrite method
 does not return an error, this object is passed back to the caller as
 part of a StreamWriteResult structure. This may be exploited to
 corrupt memory leading to a Denial of Service or potentially other
 exploits (bsc#1180553)
 * CVE-2020-8287: HTTP Request Smuggling allow two copies of a header
 field in a http request. For example, two Transfer-Encoding header
 fields. In this case Node.js identifies the first header field and
 ignores the second. This can lead to HTTP Request Smuggling
 ([link moved to references]). (bsc#1180554)
 * CVE-2020-1971: OpenSSL - EDIPARTYNAME NULL pointer de-reference (High)
 This is a vulnerability in OpenSSL which may be exploited through
 Node.js. (bsc#1179491)

New upstream LTS version 10.23.0:
 * deps: upgrade npm to 6.14.8
 * n-api:
 + create N-API version 7
 + expose napi_build_version variable");

  script_tag(name:"affected", value:"'nodejs10' package(s) on SUSE Linux Enterprise Module for Web Scripting 12");

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

if(release == "SLES12.0") {
  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.23.1~1.33.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.23.1~1.33.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.23.1~1.33.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.23.1~1.33.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.23.1~1.33.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.23.1~1.33.1", rls:"SLES12.0"))){
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
