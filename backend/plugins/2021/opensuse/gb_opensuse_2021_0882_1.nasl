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
  script_oid("1.3.6.1.4.1.25623.1.0.853863");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2021-20308");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 03:01:41 +0000 (Thu, 17 Jun 2021)");
  script_name("openSUSE: Security Advisory for htmldoc (openSUSE-SU-2021:0882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0882-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RXMQHLXPNKTCGM4HNTMLHF7NWL3ZXKIO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'htmldoc'
  package(s) announced via the openSUSE-SU-2021:0882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for htmldoc fixes the following issues:

     htmldoc was updated to version 1.9.12:

  * Fixed buffer-overflow CVE-2021-20308 ( boo#1184424 )

  * Fixed a crash bug with 'data:' URIs and EPUB output

  * Fixed several other crash bugs

  * Fixed JPEG error handling

  * Fixed some minor issues

  * Removed the bundled libjpeg, libpng, and zlib.

     update to 1.9.11:

  - Added high-resolution desktop icons for Linux.

  - Updated the internal HTTP library to fix truncation of redirection URLs

  - Fixed a regression in the handling of character entities for UTF-8 input

  - The `--numbered` option did not work when the table-of-contents was
       disabled

  - Updated local zlib to v1.2.11.

  - Updated local libpng to v1.6.37.

  - Fixed packaging issues on macOS and Windows

  - Now ignore sRGB profile errors in PNG files

  - The GUI would crash when saving

  - Page comments are now allowed in `pre` text

     update to 1.9.9:

  - Added support for a `HTMLDOC.filename` META keyword that controls the
       filename reported in CGI mode  the default remains 'htmldoc.pdf' (Issue
       #367)

  - Fixed a paragraph formatting issue with large inline images (Issue #369)

  - Fixed a buffer underflow issue (Issue #370)

  - Fixed PDF page numbers (Issue #371)

  - Added support for a new `L` header/footer format (`$LETTERHEAD`), which
       inserts a letterhead image at its full size (Issue #372, Issue #373,
       Issue #375)

  - Updated the build documentation (Issue #374)

  - Refactored the PRE rendering code to work around compiler optimization
       bugs

  - Added support for links with targets (Issue #351)

  - Fixed a table rowspan + valign bug (Issue #360)

  - Added support for data URIs (Issue #340)

  - HTMLDOC no longer includes a PDF table of contents when converting a
       single web page (Issue #344)

  - Updated the markdown support with external links, additional inline
       markup, and hard line breaks.

  - Links in markdown text no longer render with a leading space as part of
       the link (Issue #346)

  - Fixed a buffer underflow bug discovered by AddressSanitizer.

  - Fixed a bug in UTF-8 support (Issue #348)

  - PDF output now includes the base language of the input document(s)

  - Optimized the loading of font widths (Issue #354)

  - Optimized PDF page resources (Issue #356)

  - Optimized the base memory used for font widths (Issue #357)

  - Added proper `&amp shy ` support (Issue #361)

  - Title files can now be markdown.

  - The GUI did not sup ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'htmldoc' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"htmldoc", rpm:"htmldoc~1.9.12~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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