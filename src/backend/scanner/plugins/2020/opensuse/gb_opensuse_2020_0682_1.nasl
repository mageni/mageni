# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853164");
  script_version("2020-05-27T04:05:03+0000");
  script_cve_id("CVE-2020-11758", "CVE-2020-11760", "CVE-2020-11761", "CVE-2020-11762", "CVE-2020-11763", "CVE-2020-11764", "CVE-2020-11765");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-05-27 09:35:59 +0000 (Wed, 27 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-23 03:00:42 +0000 (Sat, 23 May 2020)");
  script_name("openSUSE: Security Advisory for openexr (openSUSE-SU-2020:0682-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00051.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr'
  package(s) announced via the openSUSE-SU-2020:0682-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr provides the following fix:

  Security issues fixed:

  - CVE-2020-11765: Fixed an off-by-one error in use of the ImfXdr.h read
  function by DwaCompressor:Classifier:Classifier (bsc#1169575).

  - CVE-2020-11764: Fixed an out-of-bounds write in copyIntoFrameBuffer in
  ImfMisc.cpp (bsc#1169574).

  - CVE-2020-11763: Fixed an out-of-bounds read and write, as demonstrated
  by ImfTileOffsets.cpp (bsc#1169576).

  - CVE-2020-11762: Fixed an out-of-bounds read and write in
  DwaCompressor:uncompress in ImfDwaCompressor.cpp when handling the
  UNKNOWN compression case (bsc#1169549).

  - CVE-2020-11761: Fixed an out-of-bounds read during Huffman
  uncompression, as demonstrated by FastHufDecoder:refill in
  ImfFastHuf.cpp (bsc#1169578).

  - CVE-2020-11760: Fixed an out-of-bounds read during RLE uncompression in
  rleUncompress in ImfRle.cpp (bsc#1169580).

  - CVE-2020-11758: Fixed an out-of-bounds read in
  ImfOptimizedPixelReading.h (bsc#1169573).

  Non-security issue fixed:

  - Enable tests when building the package on x86_64. (bsc#1146648)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-682=1");

  script_tag(name:"affected", value:"'openexr' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23", rpm:"libIlmImf-2_2-23~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-debuginfo", rpm:"libIlmImf-2_2-23-debuginfo~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23", rpm:"libIlmImfUtil-2_2-23~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-debuginfo", rpm:"libIlmImfUtil-2_2-23-debuginfo~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debuginfo", rpm:"openexr-debuginfo~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debugsource", rpm:"openexr-debugsource~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-devel", rpm:"openexr-devel~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-doc", rpm:"openexr-doc~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit", rpm:"libIlmImf-2_2-23-32bit~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-2_2-23-32bit-debuginfo", rpm:"libIlmImf-2_2-23-32bit-debuginfo~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit", rpm:"libIlmImfUtil-2_2-23-32bit~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmImfUtil-2_2-23-32bit-debuginfo", rpm:"libIlmImfUtil-2_2-23-32bit-debuginfo~2.2.1~lp151.4.9.1", rls:"openSUSELeap15.1"))) {
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