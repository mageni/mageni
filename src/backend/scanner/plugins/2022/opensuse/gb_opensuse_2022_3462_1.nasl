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
  script_oid("1.3.6.1.4.1.25623.1.0.822560");
  script_version("2022-10-04T10:10:56+0000");
  script_cve_id("CVE-2022-29500", "CVE-2022-29501", "CVE-2022-31251");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-10-04 10:10:56 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 04:19:00 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2022-09-30 01:03:35 +0000 (Fri, 30 Sep 2022)");
  script_name("openSUSE: Security Advisory for slurm_18_08 (SUSE-SU-2022:3462-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3462-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GVNUJDFNK4V4VDLIXNHWWG7J444S7C5A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm_18_08'
  package(s) announced via the SUSE-SU-2022:3462-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm_18_08 fixes the following issues:

  - CVE-2022-31251: Fixed a potential security vulnerability in the test
       package (bsc#1201674).

  - CVE-2022-29500: Fixed an architectural flaw can be exploited to allow an
       unprivileged user to execute arbitrary processes as root (bsc#1199278).

  - CVE-2022-29501: Fixed a vulnerability where an unprivileged user can
       send data to arbitrary unix socket as root (bsc#1199279).");

  script_tag(name:"affected", value:"'slurm_18_08' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_18_08", rpm:"libpmi0_18_08~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_18_08-debuginfo", rpm:"libpmi0_18_08-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_18_08", rpm:"perl-slurm_18_08~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_18_08-debuginfo", rpm:"perl-slurm_18_08-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08", rpm:"slurm_18_08~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-auth-none", rpm:"slurm_18_08-auth-none~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-auth-none-debuginfo", rpm:"slurm_18_08-auth-none-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-config", rpm:"slurm_18_08-config~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-config-man", rpm:"slurm_18_08-config-man~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-cray", rpm:"slurm_18_08-cray~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-cray-debuginfo", rpm:"slurm_18_08-cray-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-debuginfo", rpm:"slurm_18_08-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-debugsource", rpm:"slurm_18_08-debugsource~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-devel", rpm:"slurm_18_08-devel~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-doc", rpm:"slurm_18_08-doc~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-hdf5", rpm:"slurm_18_08-hdf5~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-hdf5-debuginfo", rpm:"slurm_18_08-hdf5-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-lua", rpm:"slurm_18_08-lua~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-lua-debuginfo", rpm:"slurm_18_08-lua-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-munge", rpm:"slurm_18_08-munge~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-munge-debuginfo", rpm:"slurm_18_08-munge-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-node", rpm:"slurm_18_08-node~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-node-debuginfo", rpm:"slurm_18_08-node-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-openlava", rpm:"slurm_18_08-openlava~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-pam_slurm", rpm:"slurm_18_08-pam_slurm~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-pam_slurm-debuginfo", rpm:"slurm_18_08-pam_slurm-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-plugins", rpm:"slurm_18_08-plugins~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-plugins-debuginfo", rpm:"slurm_18_08-plugins-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-seff", rpm:"slurm_18_08-seff~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sjstat", rpm:"slurm_18_08-sjstat~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-slurmdbd", rpm:"slurm_18_08-slurmdbd~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-slurmdbd-debuginfo", rpm:"slurm_18_08-slurmdbd-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sql", rpm:"slurm_18_08-sql~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sql-debuginfo", rpm:"slurm_18_08-sql-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sview", rpm:"slurm_18_08-sview~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sview-debuginfo", rpm:"slurm_18_08-sview-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-torque", rpm:"slurm_18_08-torque~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-torque-debuginfo", rpm:"slurm_18_08-torque-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-webdoc", rpm:"slurm_18_08-webdoc~18.08.9~150000.1.17.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_18_08", rpm:"libpmi0_18_08~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0_18_08-debuginfo", rpm:"libpmi0_18_08-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_18_08", rpm:"perl-slurm_18_08~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm_18_08-debuginfo", rpm:"perl-slurm_18_08-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08", rpm:"slurm_18_08~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-auth-none", rpm:"slurm_18_08-auth-none~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-auth-none-debuginfo", rpm:"slurm_18_08-auth-none-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-config", rpm:"slurm_18_08-config~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-config-man", rpm:"slurm_18_08-config-man~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-cray", rpm:"slurm_18_08-cray~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-cray-debuginfo", rpm:"slurm_18_08-cray-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-debuginfo", rpm:"slurm_18_08-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-debugsource", rpm:"slurm_18_08-debugsource~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-devel", rpm:"slurm_18_08-devel~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-doc", rpm:"slurm_18_08-doc~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-hdf5", rpm:"slurm_18_08-hdf5~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-hdf5-debuginfo", rpm:"slurm_18_08-hdf5-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-lua", rpm:"slurm_18_08-lua~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-lua-debuginfo", rpm:"slurm_18_08-lua-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-munge", rpm:"slurm_18_08-munge~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-munge-debuginfo", rpm:"slurm_18_08-munge-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-node", rpm:"slurm_18_08-node~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-node-debuginfo", rpm:"slurm_18_08-node-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-openlava", rpm:"slurm_18_08-openlava~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-pam_slurm", rpm:"slurm_18_08-pam_slurm~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-pam_slurm-debuginfo", rpm:"slurm_18_08-pam_slurm-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-plugins", rpm:"slurm_18_08-plugins~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-plugins-debuginfo", rpm:"slurm_18_08-plugins-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-seff", rpm:"slurm_18_08-seff~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sjstat", rpm:"slurm_18_08-sjstat~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-slurmdbd", rpm:"slurm_18_08-slurmdbd~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-slurmdbd-debuginfo", rpm:"slurm_18_08-slurmdbd-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sql", rpm:"slurm_18_08-sql~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sql-debuginfo", rpm:"slurm_18_08-sql-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sview", rpm:"slurm_18_08-sview~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-sview-debuginfo", rpm:"slurm_18_08-sview-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-torque", rpm:"slurm_18_08-torque~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-torque-debuginfo", rpm:"slurm_18_08-torque-debuginfo~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm_18_08-webdoc", rpm:"slurm_18_08-webdoc~18.08.9~150000.1.17.1", rls:"openSUSELeap15.3"))) {
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