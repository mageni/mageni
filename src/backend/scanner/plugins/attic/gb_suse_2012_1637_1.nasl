# Copyright (C) 2012 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850379");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2012-12-14 09:52:50 +0530 (Fri, 14 Dec 2012)");
  script_cve_id("CVE-2012-5130", "CVE-2012-5131", "CVE-2012-5132", "CVE-2012-5133",
                "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136", "CVE-2012-5137",
                "CVE-2012-5138");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2012:1637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"affected", value:"Chromium on openSUSE 12.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"Chromium was updated to 25.0.1343

  * Security Fixes (bnc#791234 and bnc#792154):

  - CVE-2012-5131: Corrupt rendering in the Apple OSX
  driver for Intel GPUs

  - CVE-2012-5133: Use-after-free in SVG filters.

  - CVE-2012-5130: Out-of-bounds read in Skia

  - CVE-2012-5132: Browser crash with chunked encoding

  - CVE-2012-5134: Buffer underflow in libxml.

  - CVE-2012-5135: Use-after-free with printing.

  - CVE-2012-5136: Bad cast in input element handling.

  - CVE-2012-5138: Incorrect file path handling

  - CVE-2012-5137: Use-after-free in media source handling

  - Correct build so that proprietary codecs can be used when
  the chromium-ffmpeg package is installed

  - Update to 25.0.1335

  * {gtk} Fixed <input> selection renders white text on
  white background in apps. (Issue: 158422)

  * Fixed translate infobar button to show selected
  language. (Issue: 155350)

  * Fixed broken Arabic language. (Issue: 158978)

  * Fixed pre-rendering if the preference is disabled at
  start up. (Issue: 159393)

  * Fixed JavaScript rendering issue. (Issue: 159655)

  * No further indications in the ChangeLog

  * Updated V8 - 3.14.5.0

  * Bookmarks are now searched by their title while typing
  into the omnibox with matching bookmarks being shown in
  the autocomplete suggestions pop-down list. Matching is
  done by prefix.

  * Fixed chromium issues 155871, 154173, 155133.

  - Removed patch chomium-ffmpeg-no-pkgconfig.patch

  - Building now internal libffmpegsumo.so based on the
  standard chromium ffmpeg codecs

  - Add a configuration file (/etc/default/chromium) where we
  can indicate flags for the chromium-browser.

  - add explicit buildrequire on libbz2-devel

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.850385.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


exit(66); ## This NVT is deprecated as addressed in 2013/gb_suse_2012_1637_1.nasl
