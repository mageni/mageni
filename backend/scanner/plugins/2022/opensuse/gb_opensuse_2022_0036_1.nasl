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
  script_oid("1.3.6.1.4.1.25623.1.0.854486");
  script_version("2022-02-22T09:18:02+0000");
  script_cve_id("CVE-2020-15803", "CVE-2021-27927", "CVE-2022-23134");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-29 18:15:00 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"creation_date", value:"2022-02-18 02:00:58 +0000 (Fri, 18 Feb 2022)");
  script_name("openSUSE: Security Advisory for zabbix (openSUSE-SU-2022:0036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0036-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EDFZEEJCPRPPDEWV6JULRJZVSQCMYOEY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix'
  package(s) announced via the openSUSE-SU-2022:0036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zabbix fixes the following issues:

  - Updated to latest release 4.0.37.
  Security issues fixed:

  - CVE-2022-23134: Fixed possible view of the setup pages by
       unauthenticated users if config file already exists (boo#1194681).

  - CVE-2021-27927: Fixed CSRF protection mechanism inside
       CControllerAuthenticationUpdate controller (boo#1183014).

  - CVE-2020-15803: Fixed stored XSS in the URL Widget (boo#1174253).
  Bugfixes:

  - boo#1181400: Added hardening to systemd service(s)

  - boo#1144018: Restructured for easier maintenance because FATE#324346");

  script_tag(name:"affected", value:"'zabbix' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent-debuginfo", rpm:"zabbix-agent-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-debuginfo", rpm:"zabbix-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-debugsource", rpm:"zabbix-debugsource~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-java-gateway", rpm:"zabbix-java-gateway~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-phpfrontend", rpm:"zabbix-phpfrontend~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql-debuginfo", rpm:"zabbix-proxy-mysql-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-postgresql", rpm:"zabbix-proxy-postgresql~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-postgresql-debuginfo", rpm:"zabbix-proxy-postgresql-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite", rpm:"zabbix-proxy-sqlite~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite-debuginfo", rpm:"zabbix-proxy-sqlite-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-debuginfo", rpm:"zabbix-server-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql-debuginfo", rpm:"zabbix-server-mysql-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-postgresql", rpm:"zabbix-server-postgresql~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-postgresql-debuginfo", rpm:"zabbix-server-postgresql-debuginfo~4.0.37~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
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
