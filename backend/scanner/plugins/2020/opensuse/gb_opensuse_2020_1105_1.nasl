# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853326");
  script_version("2020-08-07T07:29:19+0000");
  script_cve_id("CVE-2019-10215", "CVE-2019-15043", "CVE-2020-12245", "CVE-2020-13379");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-08-07 10:04:11 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-28 03:01:32 +0000 (Tue, 28 Jul 2020)");
  script_name("openSUSE: Security Advisory for SUSE (openSUSE-SU-2020:1105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1105-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00083.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE'
  package(s) announced via the openSUSE-SU-2020:1105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  dracut-saltboot:

  - Print a list of available disk devices (bsc#1170824)

  - Install wipefs to initrd

  - Force install crypt modules

  golang-github-prometheus-prometheus:

  - Update change log and spec file
  + Modified spec file: default to golang 1.14 to avoid 'have choice'
  build issues in OBS.
  + Rebase and update patches for version 2.18.0

  - Update to 2.18.0
  + Features

  * Tracing: Added experimental Jaeger support #7148
  + Changes

  * Federation: Only use local TSDB for federation (ignore remote read).
  #7096

  * Rules: `rule_evaluations_total` and `rule_evaluation_failures_total`
  have a `rule_group` label now. #7094
  + Enhancements

  * TSDB: Significantly reduce WAL size kept around after a block cut.
  #7098

  * Discovery: Add `architecture` meta label for EC2. #7000
  + Bug fixes

  * UI: Fixed wrong MinTime reported by /status. #7182

  * React UI: Fixed multiselect legend on OSX. #6880

  * Remote Write: Fixed blocked resharding edge case. #7122

  * Remote Write: Fixed remote write not updating on relabel configs
  change. #7073

  - Changes from 2.17.2
  + Bug fixes

  * Federation: Register federation metrics #7081

  * PromQL: Fix panic in parser error handling #7132

  * Rules: Fix reloads hanging when deleting a rule group that is being
  evaluated #7138

  * TSDB: Fix a memory leak when prometheus starts with an empty TSDB
  WAL #7135

  * TSDB: Make isolation more robust to panics in web handlers #7129
  #7136

  - Changes from 2.17.1
  + Bug fixes

  * TSDB: Fix query performance regression that increased memory and CPU
  usage #7051

  - Changes from 2.17.0
  + Features

  * TSDB: Support isolation #6841

  * This release implements isolation in TSDB. API queries and recording
  rules are guaranteed to only see full scrapes and full recording
  rules. This comes with a certain overhead in resource usage.
  Depending on the situation, there might be some increase in memory
  usage, CPU usage, or query latency.
  + Enhancements

  * PromQL: Allow more keywords as metric names #6933

  * React UI: Add normalization of localhost URLs in targets page #6794

  * Remote read: Read from remote storage concurrently #6770

  * Rules: Mark deleted rule series as stale after a reload #6745

  * Scrape: Log scrape append failures as debug rather than warn #6852

  * TSDB: Improve query performance for queries that partially hit the
  head #6676

  * Consul SD: Expose service health as meta label #5313

  * EC2 SD: Expose EC2 instance lifecycle as meta label #6914

  * Kubernetes SD: Expose service type as meta label for K8s service
  role #6684
  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'SUSE' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~0.1.1590413773.a959db7~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
