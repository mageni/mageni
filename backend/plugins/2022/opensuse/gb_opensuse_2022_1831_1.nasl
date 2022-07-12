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
  script_oid("1.3.6.1.4.1.25623.1.0.854702");
  script_version("2022-05-25T07:22:38+0000");
  script_cve_id("CVE-2022-29500", "CVE-2022-29501");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-25 10:18:04 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-25 01:02:04 +0000 (Wed, 25 May 2022)");
  script_name("openSUSE: Security Advisory for slurm_20_11 (SUSE-SU-2022:1831-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1831-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UG3NXFDYPIEMY6XALMADAPU5W5UKN4LK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm_20_11'
  package(s) announced via the SUSE-SU-2022:1831-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm_20_11 fixes the following issues:

  - CVE-2022-29500: Fixed architectural flaw that could have been exploited
       to allow an unprivileged user to execute arbitrary processes as root
       (bsc#1199278).

  - CVE-2022-29501: Fixed a problem that an unprivileged user could have
       sent data to arbitrary unix socket as root (bsc#1199279).");

  script_tag(name:"affected", value:"'slurm_20_11' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11", rpm:"libnss_slurm2_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11-debuginfo", rpm:"libnss_slurm2_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11", rpm:"libpmi0_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11-debuginfo", rpm:"libpmi0_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11", rpm:"perl-slurm_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11-debuginfo", rpm:"perl-slurm_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11", rpm:"slurm_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none", rpm:"slurm_20_11-auth-none~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none-debuginfo", rpm:"slurm_20_11-auth-none-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config", rpm:"slurm_20_11-config~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config-man", rpm:"slurm_20_11-config-man~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray", rpm:"slurm_20_11-cray~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray-debuginfo", rpm:"slurm_20_11-cray-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debuginfo", rpm:"slurm_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debugsource", rpm:"slurm_20_11-debugsource~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-devel", rpm:"slurm_20_11-devel~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-doc", rpm:"slurm_20_11-doc~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5", rpm:"slurm_20_11-hdf5~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5-debuginfo", rpm:"slurm_20_11-hdf5-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua", rpm:"slurm_20_11-lua~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua-debuginfo", rpm:"slurm_20_11-lua-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge", rpm:"slurm_20_11-munge~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge-debuginfo", rpm:"slurm_20_11-munge-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node", rpm:"slurm_20_11-node~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node-debuginfo", rpm:"slurm_20_11-node-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-openlava", rpm:"slurm_20_11-openlava~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm", rpm:"slurm_20_11-pam_slurm~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm-debuginfo", rpm:"slurm_20_11-pam_slurm-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins", rpm:"slurm_20_11-plugins~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins-debuginfo", rpm:"slurm_20_11-plugins-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest", rpm:"slurm_20_11-rest~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest-debuginfo", rpm:"slurm_20_11-rest-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-seff", rpm:"slurm_20_11-seff~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sjstat", rpm:"slurm_20_11-sjstat~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd", rpm:"slurm_20_11-slurmdbd~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd-debuginfo", rpm:"slurm_20_11-slurmdbd-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql", rpm:"slurm_20_11-sql~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql-debuginfo", rpm:"slurm_20_11-sql-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview", rpm:"slurm_20_11-sview~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview-debuginfo", rpm:"slurm_20_11-sview-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque", rpm:"slurm_20_11-torque~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque-debuginfo", rpm:"slurm_20_11-torque-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-webdoc", rpm:"slurm_20_11-webdoc~20.11.9~150200.6.10.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11", rpm:"libnss_slurm2_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_slurm2_20_11-debuginfo", rpm:"libnss_slurm2_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11", rpm:"libpmi0_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_20_11-debuginfo", rpm:"libpmi0_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11", rpm:"perl-slurm_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_20_11-debuginfo", rpm:"perl-slurm_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11", rpm:"slurm_20_11~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none", rpm:"slurm_20_11-auth-none~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-auth-none-debuginfo", rpm:"slurm_20_11-auth-none-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config", rpm:"slurm_20_11-config~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-config-man", rpm:"slurm_20_11-config-man~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray", rpm:"slurm_20_11-cray~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-cray-debuginfo", rpm:"slurm_20_11-cray-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debuginfo", rpm:"slurm_20_11-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-debugsource", rpm:"slurm_20_11-debugsource~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-devel", rpm:"slurm_20_11-devel~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-doc", rpm:"slurm_20_11-doc~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5", rpm:"slurm_20_11-hdf5~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-hdf5-debuginfo", rpm:"slurm_20_11-hdf5-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua", rpm:"slurm_20_11-lua~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-lua-debuginfo", rpm:"slurm_20_11-lua-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge", rpm:"slurm_20_11-munge~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-munge-debuginfo", rpm:"slurm_20_11-munge-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node", rpm:"slurm_20_11-node~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-node-debuginfo", rpm:"slurm_20_11-node-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-openlava", rpm:"slurm_20_11-openlava~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm", rpm:"slurm_20_11-pam_slurm~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-pam_slurm-debuginfo", rpm:"slurm_20_11-pam_slurm-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins", rpm:"slurm_20_11-plugins~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-plugins-debuginfo", rpm:"slurm_20_11-plugins-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest", rpm:"slurm_20_11-rest~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-rest-debuginfo", rpm:"slurm_20_11-rest-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-seff", rpm:"slurm_20_11-seff~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sjstat", rpm:"slurm_20_11-sjstat~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd", rpm:"slurm_20_11-slurmdbd~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-slurmdbd-debuginfo", rpm:"slurm_20_11-slurmdbd-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql", rpm:"slurm_20_11-sql~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sql-debuginfo", rpm:"slurm_20_11-sql-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview", rpm:"slurm_20_11-sview~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-sview-debuginfo", rpm:"slurm_20_11-sview-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque", rpm:"slurm_20_11-torque~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-torque-debuginfo", rpm:"slurm_20_11-torque-debuginfo~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_20_11-webdoc", rpm:"slurm_20_11-webdoc~20.11.9~150200.6.10.1", rls:"openSUSELeap15.3"))) {
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