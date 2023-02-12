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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0204.1");
  script_cve_id("CVE-2022-4254");
  script_tag(name:"creation_date", value:"2023-01-30 04:19:32 +0000 (Mon, 30 Jan 2023)");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0204-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230204-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the SUSE-SU-2023:0204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sssd fixes the following issues:

CVE-2022-4254: Fixed a bug in libsss_certmap which could allow an
 attacker to gain control of the admin account and perform a full domain
 takeover. (bsc#1207474)");

  script_tag(name:"affected", value:"'sssd' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Realtime Extension 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0", rpm:"libipa_hbac0~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac0-debuginfo", rpm:"libipa_hbac0-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0", rpm:"libsss_certmap0~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap0-debuginfo", rpm:"libsss_certmap0-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0", rpm:"libsss_idmap0~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap0-debuginfo", rpm:"libsss_idmap0-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0", rpm:"libsss_nss_idmap0~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap0-debuginfo", rpm:"libsss_nss_idmap0-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0", rpm:"libsss_simpleifp0~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp0-debuginfo", rpm:"libsss_simpleifp0-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config", rpm:"python3-sssd-config~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sssd-config-debuginfo", rpm:"python3-sssd-config-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad-debuginfo", rpm:"sssd-ad-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-32bit", rpm:"sssd-common-32bit~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-32bit-debuginfo", rpm:"sssd-common-32bit-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-debuginfo", rpm:"sssd-common-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus-debuginfo", rpm:"sssd-dbus-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-debugsource", rpm:"sssd-debugsource~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa-debuginfo", rpm:"sssd-ipa-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common-debuginfo", rpm:"sssd-krb5-common-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-debuginfo", rpm:"sssd-krb5-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap-debuginfo", rpm:"sssd-ldap-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy-debuginfo", rpm:"sssd-proxy-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools-debuginfo", rpm:"sssd-tools-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap", rpm:"sssd-winbind-idmap~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap-debuginfo", rpm:"sssd-winbind-idmap-debuginfo~1.16.1~150300.23.37.1", rls:"SLES15.0SP3"))) {
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
