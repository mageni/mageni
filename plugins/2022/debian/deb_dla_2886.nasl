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
  script_oid("1.3.6.1.4.1.25623.1.0.892886");
  script_version("2022-01-18T02:00:09+0000");
  script_cve_id("CVE-2019-12838", "CVE-2020-12693", "CVE-2020-27745", "CVE-2021-31215");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-18 10:59:48 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-18 02:00:09 +0000 (Tue, 18 Jan 2022)");
  script_name("Debian LTS: Security Advisory for slurm-llnl (DLA-2886-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/01/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2886-1");
  script_xref(name:"Advisory-ID", value:"DLA-2886-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/931880");
  script_xref(name:"URL", value:"https://bugs.debian.org/961406");
  script_xref(name:"URL", value:"https://bugs.debian.org/974721");
  script_xref(name:"URL", value:"https://bugs.debian.org/988439");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm-llnl'
  package(s) announced via the DLA-2886-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the Simple Linux Utility
for Resource Management (SLURM), a cluster resource management and job
scheduling system, which could result in denial of service,
information disclosure or privilege escalation.

CVE-2019-12838

SchedMD Slurm allows SQL Injection.

CVE-2020-12693

In the rare case where Message Aggregation is enabled, Slurm
allows Authentication Bypass via an Alternate Path or Channel. A
race condition allows a user to launch a process as an arbitrary
user.

CVE-2020-27745

RPC Buffer Overflow in the PMIx MPI plugin.

CVE-2021-31215

SchedMD Slurm allows remote code execution as SlurmUser because
use of a PrologSlurmctld or EpilogSlurmctld script leads to
environment mishandling.");

  script_tag(name:"affected", value:"'slurm-llnl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
16.05.9-1+deb9u5.

We recommend that you upgrade your slurm-llnl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0-dev", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0-dev", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm-dev", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm30", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm30-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-dev", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb30", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb30-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-client-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl-slurmdbd", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins-dev", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-doc", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-torque", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmctld-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmd-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmdbd-dbg", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"16.05.9-1+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
