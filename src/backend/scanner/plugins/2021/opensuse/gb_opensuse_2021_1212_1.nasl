# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854128");
  script_version("2021-09-03T10:01:28+0000");
  script_cve_id("CVE-2017-5753");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 17:43:00 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-09-01 01:05:00 +0000 (Wed, 01 Sep 2021)");
  script_name("openSUSE: Security Advisory for spectre-meltdown-checker (openSUSE-SU-2021:1212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1212-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5IDOTKMILRKOFD2ODQXJF3OOEYZ3EMR5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spectre-meltdown-checker'
  package(s) announced via the openSUSE-SU-2021:1212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for spectre-meltdown-checker fixes the following issues:

     spectre-meltdown-checker was updated to version 0.44 (bsc#1189477)

  - feat: add support for SRBDS related vulnerabilities

  - feat: add zstd kernel decompression (#370)

  - enh: arm: add experimental support for binary arm images

  - enh: rsb filling: no longer need the &#x27 strings&#x27  tool to check for kernel
       support in live mode

  - fix: fwdb: remove Intel extract tempdir on exit

  - fix: has_vmm: ignore kernel threads when looking for a hypervisor (fixes
       #278)

  - fix: fwdb: use the commit date as the intel fwdb version

  - fix: fwdb: update Intel&#x27 s repository URL

  - fix: arm64: CVE-2017-5753: kernels 4.19+ use a different nospec macro

  - fix: on CPU parse info under FreeBSD

  - chore: github: add check run on pull requests

  - chore: fwdb: update to v165.20201021+i20200616

     This update was imported from the SUSE:SLE-15-SP1:Update update project.");

  script_tag(name:"affected", value:"'spectre-meltdown-checker' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"spectre-meltdown-checker", rpm:"spectre-meltdown-checker~0.44~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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