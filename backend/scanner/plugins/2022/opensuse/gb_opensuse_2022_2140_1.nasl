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
  script_oid("1.3.6.1.4.1.25623.1.0.854755");
  script_version("2022-06-21T14:04:09+0000");
  script_cve_id("CVE-2022-21698");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-21 14:04:09 +0000 (Tue, 21 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 02:59:00 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-06-21 01:01:42 +0000 (Tue, 21 Jun 2022)");
  script_name("openSUSE: Security Advisory for node_exporter (SUSE-SU-2022:2140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2140-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PSXYH2FSPFD2XHUISFR5WST2W4TTXEJ5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node_exporter'
  package(s) announced via the SUSE-SU-2022:2140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update for golang-github-prometheus-node_exporter provides:
  Update golang-github-prometheus-node_exporter from version 1.1.2 to
     version 1.3.0 (bsc#1196338, jsc#SLE-24238, jsc#SLE-24239)

  - CVE-2022-21698: Denial of service using InstrumentHandlerCounter

  - Update vendor tarball with prometheus/client_golang 1.11.1

  - Update to 1.3.0

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

  - Update to 1.2.2

  * Bug fixes Fix processes collector long int parsing #2112

  - Update to 1.2.1

  * Removed Remove obsolete capture permission denied error fix already
         included upstream

  * Bug fixes Fix zoneinfo parsing prometheus/procfs#386 Fix nvme
         collector log noise #2091 Fix rapl collector log noise #2092

  - Update to 1.2.0

  * Changes Rename filesystem collector flags to match other collectors
         #2012 Make node_exporter print usage to STDOUT #203

  * Features Add conntrack statistics metrics #1155 Add ethtool stats
         collector #1832 Add flag to ignore network speed  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'node_exporter' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150100.3.12.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150100.3.12.1", rls:"openSUSELeap15.3"))) {
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