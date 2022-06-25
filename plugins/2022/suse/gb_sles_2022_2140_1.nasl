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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2140.1");
  script_cve_id("CVE-2022-21698");
  script_tag(name:"creation_date", value:"2022-06-21 04:31:16 +0000 (Tue, 21 Jun 2022)");
  script_version("2022-06-21T04:31:16+0000");
  script_tag(name:"last_modification", value:"2022-06-21 10:35:06 +0000 (Tue, 21 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 02:59:00 +0000 (Thu, 24 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2140-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222140-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node_exporter' package(s) announced via the SUSE-SU-2022:2140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update for golang-github-prometheus-node_exporter provides:

Update golang-github-prometheus-node_exporter from version 1.1.2 to version 1.3.0 (bsc#1196338, jsc#SLE-24238, jsc#SLE-24239)

CVE-2022-21698: Denial of service using InstrumentHandlerCounter

Update vendor tarball with prometheus/client_golang 1.11.1

Update to 1.3.0
 * [CHANGE] Add path label to rapl collector #2146
 * [CHANGE] Exclude filesystems under /run/credentials #2157
 * [CHANGE] Add TCPTimeouts to netstat default filter #2189
 * [FEATURE] Add lnstat collector for metrics from /proc/net/stat/ #1771
 * [FEATURE] Add darwin powersupply collector #1777
 * [FEATURE] Add support for monitoring GPUs on Linux #1998
 * [FEATURE] Add Darwin thermal collector #2032
 * [FEATURE] Add os release collector #2094
 * [FEATURE] Add netdev.address-info collector #2105
 * [FEATURE] Add clocksource metrics to time collector #2197
 * [ENHANCEMENT] Support glob textfile collector directories #1985
 * [ENHANCEMENT] ethtool: Expose node_ethtool_info metric #2080
 * [ENHANCEMENT] Use include/exclude flags for ethtool filtering #2165
 * [ENHANCEMENT] Add flag to disable guest CPU metrics #2123
 * [ENHANCEMENT] Add DMI collector #2131
 * [ENHANCEMENT] Add threads metrics to processes collector #2164
 * [ENHANCMMENT] Reduce timer GC delays in the Linux filesystem collector
 #2169
 * [ENHANCMMENT] Add TCPTimeouts to netstat default filter #2189
 * [ENHANCMMENT] Use SysctlTimeval for boottime collector on BSD #2208
 * [BUGFIX] ethtool: Sanitize metric names #2093
 * [BUGFIX] Fix ethtool collector for multiple interfaces #2126
 * [BUGFIX] Fix possible panic on macOS #2133
 * [BUGFIX] Collect flag_info and bug_info only for one core #2156
 * [BUGFIX] Prevent duplicate ethtool metric names #2187

Update to 1.2.2
 * Bug fixes Fix processes collector long int parsing #2112

Update to 1.2.1
 * Removed Remove obsolete capture permission denied error fix already
 included upstream
 * Bug fixes Fix zoneinfo parsing prometheus/procfs#386 Fix nvme
 collector log noise #2091 Fix rapl collector log noise #2092

Update to 1.2.0
 * Changes Rename filesystem collector flags to match other collectors
 #2012 Make node_exporter print usage to STDOUT #203
 * Features Add conntrack statistics metrics #1155 Add ethtool stats
 collector #1832 Add flag to ignore network speed if it is unknown
 #1989 Add tapestats collector for Linux #2044 Add nvme collector #2062
 * Enhancements Add ErrorLog plumbing to promhttp #1887 Add more
 Infiniband counters #2019 netclass: retrieve interface names and
 filter before parsing #2033 Add time zone offset metric #2060
 * Bug fixes Handle errors from disabled PSI subsystem #1983 Fix panic
 when using backwards compatible flags #2000 Fix wrong value for
 OpenBSD memory buffer cache #2015 Only initiate collectors once #2048
 Handle small backwards jumps in CPU idle #2067

Capture permission denied error for 'energy_uj' file (bsc#1190535)");

  script_tag(name:"affected", value:"'node_exporter' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150100.3.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150100.3.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150100.3.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150100.3.12.1", rls:"SLES15.0SP2"))) {
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
