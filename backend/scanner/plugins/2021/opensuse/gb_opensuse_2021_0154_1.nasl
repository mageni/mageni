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
  script_oid("1.3.6.1.4.1.25623.1.0.853748");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2018-10536", "CVE-2018-10537", "CVE-2018-10538", "CVE-2018-10539", "CVE-2018-10540", "CVE-2018-19840", "CVE-2018-19841", "CVE-2018-6767", "CVE-2018-7253", "CVE-2018-7254", "CVE-2019-1010319", "CVE-2019-11498", "CVE-2020-35738");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:39 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for wavpack (openSUSE-SU-2021:0154-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0154-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FD5IPNZ6LGJLORJOQVT3MAHBWF3ORQPT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wavpack'
  package(s) announced via the openSUSE-SU-2021:0154-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wavpack fixes the following issues:

  - Update to version 5.4.0

  * CVE-2020-35738: Fixed an out-of-bounds write in WavpackPackSamples
         (bsc#1180414)

  * fixed: disable A32 asm code when building for Apple silicon

  * fixed: issues with Adobe-style floating-point WAV files

  * added: --normalize-floats option to wvunpack for correctly exporting
         un-normalized floating-point files

  - Update to version 5.3.0

  * fixed: OSS-Fuzz issues 19925, 19928, 20060, 20448

  * fixed: trailing garbage characters on imported ID3v2 TXXX tags

  * fixed: various minor undefined behavior and memory access issues

  * fixed: sanitize tag extraction names for length and path inclusion

  * improved: reformat wvunpack 'help' and split into long + short versions

  * added: regression testing to Travis CI for OSS-Fuzz crashes

  - Updated to version 5.2.0
       *fixed: potential security issues including the following CVEs:
        CVE-2018-19840, CVE-2018-19841, CVE-2018-10536 (bsc#1091344),
        CVE-2018-10537 (bsc#1091343) CVE-2018-10538 (bsc#1091342),
        CVE-2018-10539 (bsc#1091341), CVE-2018-10540 (bsc#1091340),
        CVE-2018-7254, CVE-2018-7253, CVE-2018-6767, CVE-2019-11498 and
        CVE-2019-1010319

  * added: support for CMake, Travis CI, and Google&#x27 s OSS-fuzz

  * fixed: use correction file for encode verify (pipe input, Windows)

  * fixed: correct WAV header with actual length (pipe input, -i option)

  * fixed: thumb interworking and not needing v6 architecture (ARM asm)

  * added: handle more ID3v2.3 tag items and from all file types

  * fixed: coredump on Sparc64 (changed MD5 implementation)

  * fixed: handle invalid ID3v2.3 tags from sacd-ripper

  * fixed: several corner-case memory leaks

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'wavpack' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libwavpack1", rpm:"libwavpack1~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwavpack1-debuginfo", rpm:"libwavpack1-debuginfo~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wavpack", rpm:"wavpack~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wavpack-debuginfo", rpm:"wavpack-debuginfo~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wavpack-debugsource", rpm:"wavpack-debugsource~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wavpack-devel", rpm:"wavpack-devel~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwavpack1-32bit", rpm:"libwavpack1-32bit~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwavpack1-32bit-debuginfo", rpm:"libwavpack1-32bit-debuginfo~5.4.0~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
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
