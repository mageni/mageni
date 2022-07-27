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
  script_oid("1.3.6.1.4.1.25623.1.0.854613");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2021-36222", "CVE-2021-3711", "CVE-2021-39226", "CVE-2021-41174", "CVE-2021-41244", "CVE-2021-43798", "CVE-2021-43813", "CVE-2021-43815", "CVE-2022-21673", "CVE-2022-21702", "CVE-2022-21703", "CVE-2022-21713");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2022-05-17 12:05:28 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for SUSE (SUSE-SU-2022:1396-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1396-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ESPDBLVWSZSR5FGSXSIJXGNV5FP6I3Z5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE'
  package(s) announced via the SUSE-SU-2022:1396-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:
  grafana:

  - Update from version 7.5.12 to version 8.3.5 (jsc#SLE-23439,
       jsc#SLE-23422)
       + Security:

  * Fixes XSS vulnerability in handling data sources (bsc#1195726,
           CVE-2022-21702)

  * Fixes cross-origin request forgery vulnerability (bsc#1195727,
           CVE-2022-21703)

  * Fixes Insecure Direct Object Reference vulnerability in Teams API
           (bsc#1195728, CVE-2022-21713)

  - Update to Go 1.17.

  - Add build-time dependency on `wire`.

  - Update license to GNU Affero General Public License v3.0.

  - Update to version 8.3.4

  * GetUserInfo: return an error if no user was found (bsc#1194873,
           CVE-2022-21673)
       + Features and enhancements:

  * Alerting: Allow configuration of non-ready alertmanagers.

  * Alerting: Allow customization of Google chat message.

  * AppPlugins: Support app plugins with only default nav.

  * InfluxDB: query editor: skip fields in metadata queries.

  * Postgres/MySQL/MSSQL: Cancel in-flight SQL query if user cancels
           query in grafana.

  * Prometheus: Forward oauth tokens after prometheus datasource
           migration.
       + Bug fixes:

  * Azure Monitor: Bug fix for variable interpolations in metrics
           dropdowns.

  * Azure Monitor: Improved error messages for variable queries.

  * CloudMonitoring: Fixes broken variable queries that use group bys.

  * Configuration: You can now see your expired API keys if you have no
           active ones.

  * Elasticsearch: Fix handling multiple datalinks for a single field.

  * Export: Fix error being thrown when exporting dashboards using query
           variables that reference the default datasource.

  * ImportDashboard: Fixes issue with importing dashboard and name
           ending up in uid.

  * Login: Page no longer overflows on mobile.

  * Plugins: Set backend metadata property for core plugins.

  * Prometheus: Fill missing steps with null values.

  * Prometheus: Fix interpolation of $__rate_interval variable.

  * Prometheus: Interpolate variables with curly brackets syntax.

  * Prometheus: Respect the http-method data source setting.

  * Table: Fixes issue with field config applied to wrong fields when
           hiding columns.

  * Toolkit: Fix bug with rootUrls not being properly parsed when
           signing a private plugin.

  * Variables: Fix so data source variables are added to ad ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'SUSE' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.0~150000.1.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.16~150000.3.77.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"prometheus-postgres_exporter", rpm:"prometheus-postgres_exporter~0.10.0~150000.1.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rhnlib", rpm:"python3-rhnlib~4.2.6~150000.3.34.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.16~150000.3.77.1", rls:"openSUSELeap15.3"))) {
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