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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2259");
  script_cve_id("CVE-2019-25031", "CVE-2019-25032", "CVE-2019-25033", "CVE-2019-25034", "CVE-2019-25035", "CVE-2019-25036", "CVE-2019-25037", "CVE-2019-25038", "CVE-2019-25039", "CVE-2019-25040", "CVE-2019-25041", "CVE-2019-25042");
  script_tag(name:"creation_date", value:"2021-08-09 10:10:53 +0000 (Mon, 09 Aug 2021)");
  script_version("2021-08-09T11:38:50+0000");
  script_tag(name:"last_modification", value:"2021-08-10 10:38:07 +0000 (Tue, 10 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 22:15:00 +0000 (Fri, 11 Jun 2021)");

  script_name("Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2021-2259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2259");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2259");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2021-2259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Unbound before 1.9.5 allows configuration injection in create_unbound_ad_servers.sh upon a successful man-in-the-middle attack against a cleartext HTTP session.(CVE-2019-25031)

Unbound before 1.9.5 allows an integer overflow in the regional allocator via regional_alloc.(CVE-2019-25032)

Unbound before 1.9.5 allows an integer overflow in the regional allocator via the ALIGN_UP macro.(CVE-2019-25033)

Unbound before 1.9.5 allows an integer overflow in sldns_str2wire_dname_buf_origin, leading to an out-of-bounds write.(CVE-2019-25034)

Unbound before 1.9.5 allows an out-of-bounds write in sldns_bget_token_par.(CVE-2019-25035)

Unbound before 1.9.5 allows an assertion failure and denial of service in synth_cname.(CVE-2019-25036)

Unbound before 1.9.5 allows an assertion failure and denial of service in dname_pkt_copy via an invalid packet.(CVE-2019-25037)

Unbound before 1.9.5 allows an integer overflow in a size calculation in dnscrypt/dnscrypt.c.(CVE-2019-25038)

Unbound before 1.9.5 allows an integer overflow in a size calculation in respip/respip.c.(CVE-2019-25039)

Unbound before 1.9.5 allows an infinite loop via a compressed name in dname_pkt_copy.(CVE-2019-25040)

Unbound before 1.9.5 allows an assertion failure via a compressed name in dname_pkt_copy.(CVE-2019-25041)

Unbound before 1.9.5 allows an out-of-bounds write via a compressed name in rdata_copy.(CVE-2019-25042)");

  script_tag(name:"affected", value:"'unbound' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.7.3~18.h6.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.7.3~18.h6.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.7.3~18.h6.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
