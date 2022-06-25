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
  script_oid("1.3.6.1.4.1.25623.1.0.853792");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2018-18836", "CVE-2018-18837", "CVE-2018-18838", "CVE-2018-18839");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-02 03:00:59 +0000 (Sun, 02 May 2021)");
  script_name("openSUSE: Security Advisory for netdata (openSUSE-SU-2021:0647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0647-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7QJRCOF3ZVZ6YHKSI4ITV4ND423PKJLT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netdata'
  package(s) announced via the openSUSE-SU-2021:0647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netdata fixes the following issues:

  - Update to 1.29.3 Release v1.29.3 is a patch release to improve the
       stability of the Netdata Agent. We discovered a bug that when
       proc.plugin attempts to collect the
     operstate parameter for a virtual network interface. If the chart is
      obsoleted, the Netdata Agent crashes. This release also contains
      additional bug fixes and improvements. Bug fixes

  * Fix proc.plugin to invalidate RRDSETVAR pointers on obsoletion.

  - Update to 1.29.2 Release v1.29.2 is a patch release to improve the
       stability of the Netdata Agent. We discovered that an improvement
       introduced in v1.29.0 could inadvertently set all os_* host labels to
       unknown, which could affect users who leverage these host labels to
       organize their nodes, deploy health entities, or export metrics to
       external time-series databases. This bug has been fixed. This release
       also contains additional bug fixes and improvements. Improvements

  * Make the Opsgenie API URL configurable.

  * Add k8s_cluster_id host label.

  * Enable apps.plugin aggregation debug messages.

  * Add configuration parameter to disable stock alarms.

  * Add ACLK proxy setting as host label.

  * Add freeswitch to apps_groups.conf.

  * Simplify thread creation and remove unnecessary variables in the eBPF
         plugin. Bug fixes

  * Fix the context filtering on the data query endpoint.

  * Fix container/host detection in the system-info.sh script.

  * Add a small delay to the ipv4_tcp_resets alarms.

  * Fix collecting operstate for virtual network interfaces.

  * Fix sendmail unrecognized option F error.

  * Fix so that raw binary data should never be printed.

  * Change KSM memory chart type to stacked.

  * Allow the REMOVED alarm status via ACLK if the previous status was
         WARN/CRIT.

  * Reduce excessive logging in the ACLK.

  - Changes in 1.29.1 Release v1.29.1 is a hotfix release to address a crash
       in the Netdata Agent. A locking bug in one of the internal collectors in
       Netdata could cause it to crash during shutdown in a way that would
       result in the Netdata Agent taking an excessively long time to exit. Bug
       fixes

  * Fix crash during shutdown of cgroups internal plugin.

  - Update to 1.29.0 (go.d.plugin 0.27.0) The v1.29.0 release of the Netdata
       Agent is a maintenance release that brings incremental but necessary
       improvements that make your monitoring experience more robust. We&#x27 ve ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'netdata' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"netdata", rpm:"netdata~1.29.3~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netdata-debuginfo", rpm:"netdata-debuginfo~1.29.3~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netdata-debugsource", rpm:"netdata-debugsource~1.29.3~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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