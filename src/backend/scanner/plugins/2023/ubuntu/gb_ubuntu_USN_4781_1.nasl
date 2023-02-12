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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.4781.1");
  script_cve_id("CVE-2016-10030", "CVE-2017-15566", "CVE-2018-10995", "CVE-2018-7033", "CVE-2019-6438", "CVE-2020-12693", "CVE-2020-27745", "CVE-2020-27746", "CVE-2021-31215");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-28 17:48:00 +0000 (Thu, 28 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4781-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4781-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4781-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm-llnl' package(s) announced via the USN-4781-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Slurm incorrectly handled certain messages
between the daemon and the user. An attacker could possibly use this
issue to assume control of an arbitrary file on the system. This
issue only affected Ubuntu 16.04 ESM.
(CVE-2016-10030)

It was discovered that Slurm mishandled SPANK environment variables.
An attacker could possibly use this issue to gain elevated privileges.
This issue only affected Ubuntu 16.04 ESM. (CVE-2017-15566)

It was discovered that Slurm mishandled certain SQL queries. A local
attacker could use this issue to gain elevated privileges. This
issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and
Ubuntu 18.04 ESM. (CVE-2018-7033)

It was discovered that Slurm mishandled user names and group ids. A local
attacker could use this issue to gain administrative privileges.
This issue only affected Ubuntu 14.04 ESM and Ubuntu 18.04 ESM.
(CVE-2018-10995)

It was discovered that Slurm mishandled 23-bit systems. A local attacker
could use this to gain administrative privileges. This issue only affected
Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and Ubuntu 18.04 ESM. (CVE-2019-6438)

It was discovered that Slurm incorrectly handled certain inputs
when Message Aggregation is enabled. An attacker could possibly
use this issue to launch a process as an arbitrary user.
This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM
and Ubuntu 20.04 ESM. (CVE-2020-12693)

It was discovered that Slurm incorrectly handled certain RPC inputs.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
(CVE-2020-27745)

Jonas Stare discovered that Slurm exposes sensitive information related
to the X protocol. An attacker could possibly use this issue to obtain
a graphical session from an arbitrary user. This issue only affected
Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2020-27746)

It was discovered that Slurm incorrectly handled environment parameters.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2021-31215)");

  script_tag(name:"affected", value:"'slurm-llnl' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libslurm26", ver:"2.6.5-1ubuntu0.1~esm5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb26", ver:"2.6.5-1ubuntu0.1~esm5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-llnl", ver:"2.6.5-1ubuntu0.1~esm5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libslurm29", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb29", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"15.08.7-1ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libslurm32", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb32", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"17.11.2-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libslurm34", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"19.05.5-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
