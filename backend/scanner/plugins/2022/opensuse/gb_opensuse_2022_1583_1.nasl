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
  script_oid("1.3.6.1.4.1.25623.1.0.854683");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2022-24903");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 14:00:00 +0000 (Tue, 17 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-17 12:08:44 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for rsyslog (SUSE-SU-2022:1583-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1583-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4EUSFTBHWTVUED42DJHFNXZMUSABSNLF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsyslog'
  package(s) announced via the SUSE-SU-2022:1583-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsyslog fixes the following issues:

  - CVE-2022-24903: Fixed potential heap buffer overflow in modules for TCP
       syslog reception (bsc#1199061).");

  script_tag(name:"affected", value:"'rsyslog' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debuginfo", rpm:"rsyslog-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debugsource", rpm:"rsyslog-debugsource~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-diag-tools", rpm:"rsyslog-diag-tools~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-diag-tools-debuginfo", rpm:"rsyslog-diag-tools-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-doc", rpm:"rsyslog-doc~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-dbi", rpm:"rsyslog-module-dbi~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-dbi-debuginfo", rpm:"rsyslog-module-dbi-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-elasticsearch", rpm:"rsyslog-module-elasticsearch~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-elasticsearch-debuginfo", rpm:"rsyslog-module-elasticsearch-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gcrypt", rpm:"rsyslog-module-gcrypt~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gcrypt-debuginfo", rpm:"rsyslog-module-gcrypt-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gssapi", rpm:"rsyslog-module-gssapi~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gssapi-debuginfo", rpm:"rsyslog-module-gssapi-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gtls", rpm:"rsyslog-module-gtls~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gtls-debuginfo", rpm:"rsyslog-module-gtls-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mmnormalize", rpm:"rsyslog-module-mmnormalize~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mmnormalize-debuginfo", rpm:"rsyslog-module-mmnormalize-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mysql", rpm:"rsyslog-module-mysql~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mysql-debuginfo", rpm:"rsyslog-module-mysql-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omamqp1", rpm:"rsyslog-module-omamqp1~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omamqp1-debuginfo", rpm:"rsyslog-module-omamqp1-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omhttpfs", rpm:"rsyslog-module-omhttpfs~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omhttpfs-debuginfo", rpm:"rsyslog-module-omhttpfs-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omtcl", rpm:"rsyslog-module-omtcl~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omtcl-debuginfo", rpm:"rsyslog-module-omtcl-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-ossl", rpm:"rsyslog-module-ossl~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-ossl-debuginfo", rpm:"rsyslog-module-ossl-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-pgsql", rpm:"rsyslog-module-pgsql~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-pgsql-debuginfo", rpm:"rsyslog-module-pgsql-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-relp", rpm:"rsyslog-module-relp~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-relp-debuginfo", rpm:"rsyslog-module-relp-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-snmp", rpm:"rsyslog-module-snmp~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-snmp-debuginfo", rpm:"rsyslog-module-snmp-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-udpspoof", rpm:"rsyslog-module-udpspoof~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-udpspoof-debuginfo", rpm:"rsyslog-module-udpspoof-debuginfo~8.2106.0~150200.4.26.1", rls:"openSUSELeap15.3"))) {
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