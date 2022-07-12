# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852711");
  script_version("2019-09-27T07:41:55+0000");
  # TODO: No CVE assigned yet.  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-09-27 07:41:55 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-26 02:01:29 +0000 (Thu, 26 Sep 2019)");
  script_name("openSUSE Update for links openSUSE-SU-2019:2185-1 (links)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00068.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'links'
  package(s) announced via the openSUSE-SU-2019:2185_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for links fixes the following issues:

  links was updated to 2.20.1:

  * libevent bug fixes

  links was updated to 2.20:

  * Security bug fixed: when links was connected to tor, it would send real
  dns requests outside the tor network when the displayed page contains
  link elements with rel=dns-prefetch boo#1149886

  * stability improvements

  * file urls support local hostnames

  * mouse support improvement

  * improve interaction with Google

  * Support the zstd compression algorithm

  * Use proper cookie expiry

  links was updated to 2.19:

  * Fixed a crash on invalidn IDN URLs

  * Make font selection possible via fontconfig

  * Show certificate authority in Document info box

  * Use international error messages

  * The -dump switch didn't report errors on stdout write

  links was updated to 2.18:

  * Automatically enable tor mode when the socks port is 9050

  * When in tor mode, invert colors on top line and bottom line

  * Fix an incorrect shift in write_ev_queue

  * Fix runtime error sanitizer warning

  * Add a menu entry to save and load a clipboard

  * Don't synch with Xserver on every pixmap load

  * Fix 'Network Options' bug that caused a timeout

  * Fix a possible integer overflow in decoder_memory_expand

  * Fix possible pointer arithmetic bug if os allocated few bytes

  * Add a button to never accept invalid certs for a given server

  * Fix incorrect strings -html-t-text-color

  * Add ascii replacement of Romanian S and T with comma

  * Fix a bug when IPv6 control connection to ftp server fails

  links was updated to 2.17:

  * Fix verifying SSL certificates for numeric IPv6 addresses

  * Delete the option -ftp.fast - it doesn't always work and ftp performance
  is not an issue anymore

  * Add bold and monospaced Turkish letter 'i' without a dot

  * On OS/2 allocate OpenSSL memory from the lower heap. It fixes SSL on
  systems with old 16-bit TCP/IP stack

  * Fix IPv6 on OpenVMS Alpha

  * Support mouse scroll wheel in textarea

  * Delete the option -http-bugs.bug-302-redirect - RFC7231 allows the
  'buggy' behavior and defines new codes 307 and 308 that retain the post
  data

  * X11 - fixed colormap leak when creating a new window

  * Fixed an infinite loop that happened in graphics mode if the user
  clicked on OK in 'Miscellaneous options' dialog and more than one
  windows were open. This bug was introduced in Links 2.15

  * Support 6x6x6 RGB palette in 256-bit color mode on framebuffer

  * Implement dithering properly on OS/2 in 15-bit and 16-bit color mode. In
  8-bit mode, Links may optionally use a private palette - it improves
  visual quality  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'links' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"links", rpm:"links~2.20.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"links-debuginfo", rpm:"links-debuginfo~2.20.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"links-debugsource", rpm:"links-debugsource~2.20.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
