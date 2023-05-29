# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2183.1");
  script_cve_id("CVE-2022-27191", "CVE-2022-27664", "CVE-2022-41715", "CVE-2022-46146");
  script_tag(name:"creation_date", value:"2023-05-12 04:21:00 +0000 (Fri, 12 May 2023)");
  script_version("2023-05-12T09:09:03+0000");
  script_tag(name:"last_modification", value:"2023-05-12 09:09:03 +0000 (Fri, 12 May 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 16:09:00 +0000 (Fri, 02 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2183-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232183-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2023:2183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:
golang-github-prometheus-alertmanager:

Security issues fixed:
CVE-2022-46146: Fix authentication bypass via cache poisoning (bsc#1208051)

prometheus-blackbox_exporter:

Security issues fixed:
CVE-2022-46146: Fix authentication bypass via cache poisoning (bsc#1208062)
Other non-security bugs fixed and changes:
Add min_version parameter of tls_config to allow enabling TLS 1.0 and 1.1 (bsc#1209113)
On SUSE Linux Enterprise build always with Go >= 1.19 (bsc#1203599)

prometheus-postgres_exporter:

Security issues fixed:
CVE-2022-46146: Fix authentication bypass via cache poisoning (bsc#1208060)
Other non-security issues fixed:
Adapt the systemd service security configuration to be able to start it on for Red Hat Linux Enterprise systems and
 clones Create the prometheus user for Red Hat Linux Enterprise systems and clones Fix broken log-level for values other than debug (bsc#1208965)

golang-github-prometheus-node_exporter:

Security issues fixed in this version update to version 1.5.0 (jsc#PED-3578):
CVE-2022-27191: Update go/x/crypto (bsc#1197284)
CVE-2022-27664: Update go/x/net (bsc#1203185)
CVE-2022-46146: Update exporter-toolkit (bsc#1208064)
Other non-security bug fixes and changes in this version update to 1.5.0 (jsc#PED-3578):
NOTE: This changes the Go runtime 'GOMAXPROCS' to 1. This is done to limit the concurrency of the exporter to 1 CPU
 thread at a time in order to avoid a race condition problem in the Linux kernel and parallel IO issues on nodes
 with high numbers of CPUs/CPU threads.
[BUGFIX] Fix hwmon label sanitizer
[BUGFIX] Use native endianness when encoding InetDiagMsg
[BUGFIX] Fix btrfs device stats always being zero
[BUGFIX] Fix diskstats exclude flags
[BUGFIX] [node-mixin] Fix fsSpaceAvailableCriticalThreshold and fsSpaceAvailableWarning
[BUGFIX] Fix concurrency issue in ethtool collector
[BUGFIX] Fix concurrency issue in netdev collector
[BUGFIX] Fix diskstat reads and write metrics for disks with different sector sizes
[BUGFIX] Fix iostat on macos broken by deprecation warning
[BUGFIX] Fix NodeFileDescriptorLimit alerts
[BUGFIX] Sanitize rapl zone names
[BUGFIX] Add file descriptor close safely in test
[BUGFIX] Fix race condition in os_release.go
[BUGFIX] Skip ZFS IO metrics if their paths are missing
[BUGFIX] Handle nil CPU thermal power status on M1
[BUGFIX] bsd: Ignore filesystems flagged as MNT_IGNORE
[BUGFIX] Sanitize UTF-8 in dmi collector
[CHANGE] Merge metrics descriptions in textfile collector
[FEATURE] Add multiple listeners and systemd socket listener activation
[FEATURE] [node-mixin] Add darwin dashboard to mixin
[FEATURE] Add 'isolated' metric on cpu collector on linux
[FEATURE] Add cgroup summary collector
[FEATURE] Add selinux collector
[FEATURE] Add slab info collector
[FEATURE] Add sysctl collector
[FEATURE] Also track the CPU Spin time for OpenBSD systems
[FEATURE] Add support for MacOS ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Manager Client Tools for SLE 12, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.5.0~1.24.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.5.0~1.24.4", rls:"SLES12.0SP5"))) {
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
