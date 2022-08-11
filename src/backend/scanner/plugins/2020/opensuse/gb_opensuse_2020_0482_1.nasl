# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.853101");
  script_version("2020-04-10T03:46:49+0000");
  script_cve_id("CVE-2017-1000126", "CVE-2017-9239", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-17229", "CVE-2018-17230", "CVE-2018-17282", "CVE-2018-19108", "CVE-2018-19607", "CVE-2018-9305", "CVE-2019-13114");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-14 09:52:40 +0000 (Tue, 14 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-09 03:08:25 +0000 (Thu, 09 Apr 2020)");
  script_name("openSUSE: Security Advisory for exiv2 (openSUSE-SU-2020:0482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2'
  package(s) announced via the openSUSE-SU-2020:0482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:

  exiv2 was updated to latest 0.26 branch, fixing bugs and security issues:

  - CVE-2017-1000126: Fixed an out of bounds read in webp parser
  (bsc#1068873).

  - CVE-2017-9239: Fixed a segmentation fault in
  TiffImageEntry::doWriteImage function (bsc#1040973).

  - CVE-2018-12264: Fixed an integer overflow in LoaderTiff::getData() which
  might have led to an out-of-bounds read (bsc#1097600).

  - CVE-2018-12265: Fixed integer overflows in LoaderExifJpeg which could
  have led to memory corruption (bsc#1097599).

  - CVE-2018-17229: Fixed a heap based buffer overflow in Exiv2::d2Data via
  a crafted image (bsc#1109175).

  - CVE-2018-17230: Fixed a heap based buffer overflow in Exiv2::d2Data via
  a crafted image (bsc#1109176).

  - CVE-2018-17282: Fixed a null pointer dereference in
  Exiv2::DataValue::copy (bsc#1109299).

  - CVE-2018-19108: Fixed an integer overflow in
  Exiv2::PsdImage::readMetadata which could have led to infinite loop
  (bsc#1115364).

  - CVE-2018-19607: Fixed a null pointer dereference in Exiv2::isoSpeed
  which might have led to denial
  of service (bsc#1117513).

  - CVE-2018-9305:  Fixed an out of bounds read in IptcData::printStructure
  which might have led to to information leak or denial of service
  (bsc#1088424).

  - CVE-2019-13114: Fixed a null pointer dereference which might have led to
  denial of service via a crafted response of an malicious http server
  (bsc#1142684).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-482=1");

  script_tag(name:"affected", value:"'exiv2' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-doc", rpm:"libexiv2-doc~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-32bit", rpm:"libexiv2-26-32bit~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-32bit-debuginfo", rpm:"libexiv2-26-32bit-debuginfo~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-lang", rpm:"exiv2-lang~0.26~lp151.7.3.1", rls:"openSUSELeap15.1"))) {
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