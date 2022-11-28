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
  script_oid("1.3.6.1.4.1.25623.1.0.822864");
  script_version("2022-11-22T10:12:16+0000");
  script_cve_id("CVE-2022-39377");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-22 10:12:16 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-18 02:13:48 +0000 (Fri, 18 Nov 2022)");
  script_name("Fedora: Security Advisory for sysstat (FEDORA-2022-5adda2d05f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-5adda2d05f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7X6WKTODOUDV6M3HZMASYNZP6EM4N7W4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sysstat'
  package(s) announced via the FEDORA-2022-5adda2d05f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The sysstat package contains the sar, sadf, mpstat, iostat, tapestat,
pidstat, cifsiostat and sa tools for Linux.
The sar command collects and reports system activity information.
The information collected by sar can be saved in a file in a binary
format for future inspection. The statistics reported by sar concern
I/O transfer rates, paging activity, process-related activities,
interrupts, network activity, memory and swap space utilization, CPU
utilization, kernel activities and TTY statistics, among others. Both
UP and SMP machines are fully supported.
The sadf command may  be used to display data collected by sar in
various formats (CSV, PCP, XML, etc.).
The iostat command reports CPU utilization and I/O statistics for disks.
The tapestat command reports statistics for tapes connected to the system.
The mpstat command reports global and per-processor statistics.
The pidstat command reports statistics for Linux tasks (processes).
The cifsiostat command reports I/O statistics for CIFS file systems.");

  script_tag(name:"affected", value:"'sysstat' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"sysstat", rpm:"sysstat~12.5.6~2.fc35", rls:"FC35"))) {
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