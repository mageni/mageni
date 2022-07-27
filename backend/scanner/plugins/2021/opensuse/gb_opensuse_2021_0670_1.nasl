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
  script_oid("1.3.6.1.4.1.25623.1.0.853796");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2021-20296", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3477", "CVE-2021-3479");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-06 03:03:10 +0000 (Thu, 06 May 2021)");
  script_name("openSUSE: Security Advisory for openexr (openSUSE-SU-2021:0670-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0670-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XRXYHURHLDTSCIDOVAICJNNLPZTJP6NQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2021:0670-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr fixes the following issues:

  - CVE-2021-23215: Fixed an integer-overflow in
       Imf_2_5:DwaCompressor:initializeBuffers (bsc#1185216).

  - CVE-2021-26260: Fixed an Integer-overflow in
       Imf_2_5:DwaCompressor:initializeBuffers (bsc#1185217).

  - CVE-2021-20296: Fixed a  Null Pointer dereference in
       Imf_2_5:hufUncompress (bsc#1184355).

  - CVE-2021-3477: Fixed a Heap-buffer-overflow in
       Imf_2_5::DeepTiledInputFile::readPixelSampleCounts (bsc#1184353).

  - CVE-2021-3479: Fixed an Out-of-memory caused by allocation of a very
       large buffer (bsc#1184354).

     This update was imported from the SUSE:SLE-15:Update update project.");

  script_tag(name:"affected", value:"'openexr' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23", rpm:"libIlmImf-2_2-23~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-debuginfo", rpm:"libIlmImf-2_2-23-debuginfo~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23", rpm:"libIlmImfUtil-2_2-23~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-debuginfo", rpm:"libIlmImfUtil-2_2-23-debuginfo~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debuginfo", rpm:"openexr-debuginfo~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debugsource", rpm:"openexr-debugsource~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-devel", rpm:"openexr-devel~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-doc", rpm:"openexr-doc~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit", rpm:"libIlmImf-2_2-23-32bit~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit-debuginfo", rpm:"libIlmImf-2_2-23-32bit-debuginfo~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit", rpm:"libIlmImfUtil-2_2-23-32bit~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit-debuginfo", rpm:"libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~lp152.7.14.1", rls:"openSUSELeap15.2"))) {
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