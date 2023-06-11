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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2105");
  script_cve_id("CVE-2022-2795", "CVE-2022-3080", "CVE-2022-3094", "CVE-2022-3736", "CVE-2022-38177", "CVE-2022-38178", "CVE-2022-3924");
  script_tag(name:"creation_date", value:"2023-06-07 04:14:30 +0000 (Wed, 07 Jun 2023)");
  script_version("2023-06-07T05:05:00+0000");
  script_tag(name:"last_modification", value:"2023-06-07 05:05:00 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 16:28:00 +0000 (Mon, 06 Feb 2023)");

  script_name("Huawei EulerOS: Security Advisory for bind (EulerOS-SA-2023-2105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2105");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2105");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bind' package(s) announced via the EulerOS-SA-2023-2105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Bind package. By spoofing the target resolver with responses that have a malformed ECDSA signature, an attacker can trigger a small memory leak, resulting in crashing the program.(CVE-2022-38177)

By flooding the target resolver with queries exploiting this flaw an attacker can significantly impair the resolver's performance, effectively denying legitimate clients access to the DNS resolution service.(CVE-2022-2795)

A flaw was found in the Bind package, where the DNSSEC verification code for the EdDSA algorithm leaks memory when there is a signature length mismatch. By spoofing the target resolver with responses that have a malformed EdDSA signature, an attacker can trigger a small memory leak, resulting in crashing the program.(CVE-2022-38178)

A flaw was found in the Bind package, where the resolver can crash when stale cache and stale answers are enabled, option stale-answer-client-timeout is set to 0 and there is a stale CNAME in the cache for an incoming query. By sending specific queries to the resolver, an attacker can cause named to crash.(CVE-2022-3080)

Sending a flood of dynamic DNS updates may cause `named` to allocate large amounts of memory. This, in turn, may cause `named` to exit due to a lack of free memory. We are not aware of any cases where this has been exploited. Memory is allocated prior to the checking of access permissions (ACLs) and is retained during the processing of a dynamic update from a client whose access credentials are accepted. Memory allocated to clients that are not permitted to send updates is released immediately upon rejection. The scope of this vulnerability is limited therefore to trusted clients who are permitted to make dynamic zone changes. If a dynamic update is REFUSED, memory will be released again very quickly. Therefore it is only likely to be possible to degrade or stop `named` by sending a flood of unaccepted dynamic updates comparable in magnitude to a query flood intended to achieve the same detrimental outcome. BIND 9.11 and earlier branches are also affected, but through exhaustion of internal resources rather than memory constraints. This may reduce performance but should not be a significant problem for most servers. Therefore we don't intend to address this for BIND versions prior to BIND 9.16. This issue affects BIND 9 versions 9.16.0 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.8-S1 through 9.16.36-S1.(CVE-2022-3094)

BIND 9 resolver can crash when stale cache and stale answers are enabled, option `stale-answer-client-timeout` is set to a positive integer, and the resolver receives an RRSIG query. This issue affects BIND 9 versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.12-S1 through 9.16.36-S1.(CVE-2022-3736)

This issue can affect BIND 9 resolvers with `stale-answer-enable yes,` that also make use of the option ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'bind' package(s) on Huawei EulerOS Virtualization release 2.11.0.");

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

if(release == "EULEROSVIRT-2.11.0") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-doc", rpm:"bind-dnssec-doc~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-dnssec-utils", rpm:"bind-dnssec-utils~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11", rpm:"bind-pkcs11~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-libs", rpm:"bind-pkcs11-libs~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-utils", rpm:"bind-pkcs11-utils~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.23~6.h11.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
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
