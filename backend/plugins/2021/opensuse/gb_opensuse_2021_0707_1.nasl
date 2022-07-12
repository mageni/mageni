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
  script_oid("1.3.6.1.4.1.25623.1.0.853803");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2021-22204");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-12 03:03:13 +0000 (Wed, 12 May 2021)");
  script_name("openSUSE: Security Advisory for perl-Image-ExifTool (openSUSE-SU-2021:0707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0707-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SLQ4XG6SNL6OL7SHPBZLVWYCAEZGZW5X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Image-ExifTool'
  package(s) announced via the openSUSE-SU-2021:0707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-Image-ExifTool fixes the following issues:

     Update to version 12.25 fixes (boo#1185547 CVE-2021-22204)

  * JPEG XL support is now official

  * Added read support for Medical Research Council (MRC) image files

  * Added ability to write a number of 3gp tags in video files

  * Added a new Sony PictureProfile value (thanks Jos Roost)

  * Added a new Sony LensType (thanks LibRaw)

  * Added a new Nikon LensID (thanks Niels Kristian Bech Jensen)

  * Added a new Canon LensType

  * Decode more GPS information from Blackvue dashcam videos

  * Decode a couple of new NikonSettings tags (thanks Warren Hatch)

  * Decode a few new RIFF tags

  * Improved Validate option to add minor warning if standard XMP is missing
       xpacket wrapper

  * Avoid decoding some large arrays in DNG images to improve performance
       unless the -m option is used

  * Patched bug that could give runtime warning when trying to write an
       empty XMP structure

  * Fixed decoding of ImageWidth/Height for JPEG XL images

  * Fixed problem were Microsoft Xtra tags couldn&#x27 t be deleted

     version 12.24:

  * Added a new PhaseOne RawFormat value (thanks LibRaw)

  * Decode a new Sony tag (thanks Jos Roost)

  * Decode a few new Panasonic and FujiFilm tags (thanks LibRaw and
       Greybeard)

  * Patched security vulnerability in DjVu reader

  * Updated acdsee.config in distribution (thanks StarGeek)

  * Recognize AutoCAD DXF files

  * More work on experimental JUMBF read support

  * More work on experimental JPEG XL read/write support

     version 12.23:

  * Added support for Olympus ORI files

  * Added experimental read/write support for JPEG XL images

  * Added experimental read support for JUMBF metadata in JPEG and Jpeg2000
       images

  * Added built-in support for parsing GPS track from Denver ACG-8050 videos
       with the -ee option

  * Added a some new Sony lenses (thanks Jos Roost and LibRaw)

  * Changed priority of Samsung trailer tags so the first DepthMapImage
       takes precedence when -a is not used

  * Improved identification of M4A audio files

  * Patched to avoid escaping &#x27, &#x27  in 'Binary data' message when

  - struct is used

  * Removed Unknown flag from MXF VideoCodingSchemeID tag

  * Fixed -forcewrite=EXIF to apply to EXIF in binary header of EPS files

  * API Changes:
       + Added BlockExtract option

     version 12.22:

  * Added a few new Sony LensTypes and a new SonyModelID (thanks Jos Roost
       and LibRaw)

  * Added Extr ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'perl-Image-ExifTool' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"exiftool", rpm:"exiftool~12.25~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-RandomAccess", rpm:"perl-File-RandomAccess~12.25~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-ExifTool", rpm:"perl-Image-ExifTool~12.25~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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