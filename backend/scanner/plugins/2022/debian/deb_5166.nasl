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
  script_oid("1.3.6.1.4.1.25623.1.0.705166");
  script_version("2022-06-24T14:04:41+0000");
  script_cve_id("CVE-2022-29500", "CVE-2022-29501");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-24 14:04:41 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 04:19:00 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2022-06-21 01:00:21 +0000 (Tue, 21 Jun 2022)");
  script_name("Debian: Security Advisory for slurm-wlm (DSA-5166-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5166.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5166-1");
  script_xref(name:"Advisory-ID", value:"DSA-5166-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm-wlm'
  package(s) announced via the DSA-5166-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues were discovered in the Simple Linux Utility for
Resource Management (SLURM), a cluster resource management and job
scheduling system, which could result in privilege escalation.");

  script_tag(name:"affected", value:"'slurm-wlm' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 20.11.7+really20.11.4-2+deb11u1.

We recommend that you upgrade your slurm-wlm packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm-adopt", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi0-dev", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0-dev", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm-dev", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurm36", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins-dev", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-doc", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-torque", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slurmrestd", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"20.11.7+really20.11.4-2+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
