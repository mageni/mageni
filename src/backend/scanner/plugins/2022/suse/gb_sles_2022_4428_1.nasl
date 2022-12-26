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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4428.1");
  script_cve_id("CVE-2021-36222", "CVE-2021-3711", "CVE-2021-41174", "CVE-2021-41244", "CVE-2021-43798", "CVE-2021-43813", "CVE-2021-43815", "CVE-2022-29170", "CVE-2022-31097", "CVE-2022-31107", "CVE-2022-35957", "CVE-2022-36062");
  script_tag(name:"creation_date", value:"2022-12-14 04:18:35 +0000 (Wed, 14 Dec 2022)");
  script_version("2022-12-14T10:20:42+0000");
  script_tag(name:"last_modification", value:"2022-12-14 10:20:42 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4428-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4428-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224428-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana' package(s) announced via the SUSE-SU-2022:4428-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

Version update from 8.3.10 to 8.5.13 (jsc#PED-2145):

Security fixes:
 * CVE-2022-36062: (bsc#1203596)
 * CVE-2022-35957: (bsc#1203597)
 * CVE-2022-31107: (bsc#1201539)
 * CVE-2022-31097: (bsc#1201535)
 * CVE-2022-29170: (bsc#1199810)
 * CVE-2021-43813, CVE-2021-43815: (bsc#1193686)
 * CVE-2021-43798: (bsc#1193492)
 * CVE-2021-41244: (bsc#1192763)
 * CVE-2021-41174: (bsc#1192383)
 * CVE-2021-3711: (bsc#1189520)
 * CVE-2021-36222: (bsc#1188571)

Features and enhancements:
 * AccessControl: Disable user remove and user update roles when they do
 not have the permissions
 * AccessControl: Provisioning for teams
 * Alerting: Add custom grouping to Alert Panel
 * Alerting: Add safeguard for migrations that might cause dataloss
 * Alerting: AlertingProxy to elevate permissions for request forwarded
 to data proxy when RBAC enabled
 * Alerting: Grafana uses > instead of >= when checking the For duration
 * Alerting: Move slow queries in the scheduler to another goroutine
 * Alerting: Remove disabled flag for data source when migrating alerts
 * Alerting: Show notification tab of legacy alerting only to editor
 * Alerting: Update migration to migrate only alerts that belon to
 existing org\dashboard
 * Alerting: Use expanded labels in dashboard annotations
 * Alerting: Use time.Ticker instead of alerting.Ticker in ngalert
 * Analytics: Add user id tracking to google analytics
 * Angular: Add AngularJS plugin support deprecation plan to docs site
 * API: Add usage stats preview endpoint
 * API: Extract OpenAPI specification from source code using go-swagger
 * Auth: implement auto_sign_up for auth.jwt
 * Azure monitor Logs: Optimize data fetching in resource picker
 * Azure Monitor Logs: Order subscriptions in resource picker by name
 * Azure Monitor: Include datasource ref when interpolating variables.
 * AzureMonitor: Add support for not equals and startsWith operators when
 creating Azure Metrics dimension filters.
 * AzureMonitor: Do not quote variables when a custom 'All' variable
 option is used
 * AzureMonitor: Filter list of resources by resourceType
 * AzureMonitor: Update allowed namespaces
 * BarChart: color by field, x time field, bar radius, label skipping
 * Chore: Implement OpenTelemetry in Grafana
 * Cloud Monitoring: Adds metric type to Metric drop down options
 * CloudMonitor: Correctly encode default project response
 * CloudWatch: Add all ElastiCache Redis Metrics
 * CloudWatch: Add Data Lifecycle Manager metrics and dimension
 * CloudWatch: Add Missing Elasticache Host-level metrics
 * CloudWatch: Add multi-value template variable support for log group
 names in logs query builder
 * CloudWatch: Add new AWS/ES metrics. #43034, @sunker
 * Cloudwatch: Add support for AWS/PrivateLink* metrics and dimensions
 * Cloudwatch: Add support for new AWS/RDS EBS* metrics
 * Cloudwatch: Add syntax highlighting and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grafana' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~8.5.13~150200.3.29.5", rls:"SLES15.0SP4"))) {
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
