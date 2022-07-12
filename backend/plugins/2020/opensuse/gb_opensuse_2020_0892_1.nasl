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
  script_oid("1.3.6.1.4.1.25623.1.0.853237");
  script_version("2020-06-30T06:18:22+0000");
  script_cve_id("CVE-2019-15043", "CVE-2020-12245", "CVE-2020-13379");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-06-30 10:45:10 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-29 03:00:57 +0000 (Mon, 29 Jun 2020)");
  script_name("openSUSE: Security Advisory for grafana, (openSUSE-SU-2020:0892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:0892-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00060.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana, '
  package(s) announced via the openSUSE-SU-2020:0892-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana, grafana-piechart-panel, grafana-status-panel
  fixes the following issues:

  grafana was updated to version 7.0.3:

  * Features / Enhancements

  - Stats: include all fields. #24829, @ryantxu

  - Variables: change VariableEditorList row action Icon to IconButton.
  #25217, @hshoff

  * Bug fixes

  - Cloudwatch: Fix dimensions of DDoSProtection. #25317, @papagian

  - Configuration: Fix env var override of sections containing hyphen.
  #25178, @marefr

  - Dashboard: Get panels in collapsed rows. #25079, @peterholmberg

  - Do not show alerts tab when alerting is disabled. #25285, @dprokop

  - Jaeger: fixes cascader option label duration value. #25129, @Estrax

  - Transformations: Fixed Transform tab crash & no update after adding
  first transform. #25152, @torkelo

  Update to version 7.0.2

  * Bug fixes

  - Security: Urgent security patch release to fix CVE-2020-13379

  Update to version 7.0.1

  * Features / Enhancements

  - Datasource/CloudWatch: Makes CloudWatch Logs query history more
  readable. #24795, @kaydelaney

  - Download CSV: Add date and time formatting. #24992, @ryantxu

  - Table: Make last cell value visible when right aligned. #24921,
  @peterholmberg

  - TablePanel: Adding sort order persistence. #24705, @torkelo

  - Transformations: Display correct field name when using reduce
  transformation. #25068, @peterholmberg

  - Transformations: Allow custom number input for binary operations.
  #24752, @ryantxu

  * Bug fixes

  - Dashboard/Links: Fixes dashboard links by tags not working. #24773,
  @KamalGalrani

  - Dashboard/Links: Fixes open in new window for dashboard link. #24772,
  @KamalGalrani

  - Dashboard/Links: Variables are resolved and limits to 100. #25076,
  @hugohaggmark

  - DataLinks: Bring back variables interpolation in title. #24970,
  @dprokop

  - Datasource/CloudWatch: Field suggestions no longer limited to
  prefix-only. #24855, @kaydelaney

  - Explore/Table: Keep existing field types if possible. #24944,
  @kaydelaney

  - Explore: Fix wrap lines toggle for results of queries with filter
  expression. #24915, @ivanahuckova

  - Explore: fix undo in query editor. #24797, @zoltanbedi

  - Explore: fix word break in type head info. #25014, @zoltanbedi

  - Graph: Legend decimals now work as expected. #24931, @torkelo

  - LoginPage: Fix hover color for service buttons. #25009, @tskarhed

  - LogsPanel: Fix scrollbar. #24850, @ivanahuckova

  - MoveDashboard: Fix for moving dashboard caused all variables to be
  lost. #25005, @torkelo

  - Organize transformer: Use display name in field order comparer.
  #24984, @dprokop

  - Panel:  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'grafana, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~7.0.3~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana-debuginfo", rpm:"grafana-debuginfo~7.0.3~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana-piechart-panel", rpm:"grafana-piechart-panel~1.4.0~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana-status-panel", rpm:"grafana-status-panel~1.0.9~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
