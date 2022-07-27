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
  script_oid("1.3.6.1.4.1.25623.1.0.854023");
  script_version("2021-08-03T06:52:21+0000");
  script_cve_id("CVE-2020-29663", "CVE-2021-32739", "CVE-2021-32743");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-03 10:35:54 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-25 03:01:31 +0000 (Sun, 25 Jul 2021)");
  script_name("openSUSE: Security Advisory for icinga2 (openSUSE-SU-2021:1089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1089-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AG46DROWC4ZEVBNIZC5IYVVFYH4FMFCS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icinga2'
  package(s) announced via the openSUSE-SU-2021:1089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icinga2 fixes the following issues:

     icinga2 was updated to 2.12.5:

       Version 2.12.5 fixes two security vulnerabilities that may lead to
     privilege escalation for authenticated API users. Other improvements
     include several bugfixes related to downtimes, downtime notifications, and
     more reliable connection handling.

  * Security

  - Don&#x27 t expose the PKI ticket salt via the API. This may lead to
           privilege escalation for authenticated API users by them being able
           to request certificates for other identities (CVE-2021-32739)

  - Don&#x27 t expose IdoMysqlConnection, IdoPgsqlConnection, and
           ElasticsearchWriter passwords via the API (CVE-2021-32743)

         Depending on your setup, manual intervention beyond installing the new
     versions may be required, so please read the more detailed information in
     the release blog post carefully.

  * Bugfixes

  - Don&#x27 t send downtime end notification if downtime hasn&#x27 t started #8878

  - Don&#x27 t let a failed downtime creation block the others #8871

  - Support downtimes and comments for checkables with long names #8870

  - Trigger fixed downtimes immediately if the current time matches
           (instead of waiting for the timer) #8891

  - Add configurable timeout for full connection handshake #8872

  * Enhancements

  - Replace existing downtimes on ScheduledDowntime change #8880

  - Improve crashlog #8869");

  script_tag(name:"affected", value:"'icinga2' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"icinga2", rpm:"icinga2~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin", rpm:"icinga2-bin~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin-debuginfo", rpm:"icinga2-bin-debuginfo~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-common", rpm:"icinga2-common~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debuginfo", rpm:"icinga2-debuginfo~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debugsource", rpm:"icinga2-debugsource~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-doc", rpm:"icinga2-doc~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql", rpm:"icinga2-ido-mysql~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql-debuginfo", rpm:"icinga2-ido-mysql-debuginfo~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql", rpm:"icinga2-ido-pgsql~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql-debuginfo", rpm:"icinga2-ido-pgsql-debuginfo~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nano-icinga2", rpm:"nano-icinga2~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-icinga2", rpm:"vim-icinga2~2.12.5~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
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