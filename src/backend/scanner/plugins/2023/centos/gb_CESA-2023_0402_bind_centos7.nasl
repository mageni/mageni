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
  script_oid("1.3.6.1.4.1.25623.1.0.884258");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2021-25220", "CVE-2022-2795");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 18:14:00 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"creation_date", value:"2023-01-31 02:01:04 +0000 (Tue, 31 Jan 2023)");
  script_name("CentOS: Security Advisory for bind (CESA-2023:0402)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:0402");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-January/086358.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the CESA-2023:0402 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
Name System (DNS) protocols. BIND includes a DNS server (named), a resolver
library (routines for applications to use when interfacing with DNS), and
tools for verifying that the DNS server is operating correctly.

Security Fix(es):

  * bind: DNS forwarders - cache poisoning vulnerability (CVE-2021-25220)

  * bind: processing large delegations may severely degrade resolver
performance (CVE-2022-2795)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'bind' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-export-devel", rpm:"bind-export-devel~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-export-libs", rpm:"bind-export-libs~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-lite", rpm:"bind-libs-lite~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lite-devel", rpm:"bind-lite-devel~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11", rpm:"bind-pkcs11~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-devel", rpm:"bind-pkcs11-devel~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-libs", rpm:"bind-pkcs11-libs~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-pkcs11-utils", rpm:"bind-pkcs11-utils~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-sdb-chroot", rpm:"bind-sdb-chroot~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.4~26.P2.el7_9.13", rls:"CentOS7"))) {
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