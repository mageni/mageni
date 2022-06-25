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
  script_oid("1.3.6.1.4.1.25623.1.0.853320");
  script_version("2020-08-07T07:29:19+0000");
  script_cve_id("CVE-2020-11017", "CVE-2020-11018", "CVE-2020-11019", "CVE-2020-11038", "CVE-2020-11039", "CVE-2020-11040", "CVE-2020-11041", "CVE-2020-11043", "CVE-2020-11085", "CVE-2020-11086", "CVE-2020-11087", "CVE-2020-11088", "CVE-2020-11089", "CVE-2020-11095", "CVE-2020-11096", "CVE-2020-11097", "CVE-2020-11098", "CVE-2020-11099", "CVE-2020-11521", "CVE-2020-11522", "CVE-2020-11523", "CVE-2020-11524", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398", "CVE-2020-4030", "CVE-2020-4031", "CVE-2020-4032", "CVE-2020-4033");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-07 10:04:11 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 03:01:27 +0000 (Mon, 27 Jul 2020)");
  script_name("openSUSE: Security Advisory for freerdp (openSUSE-SU-2020:1090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1090-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00080.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp'
  package(s) announced via the openSUSE-SU-2020:1090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

  frerdp was updated to version 2.1.2 (bsc#1171441, bsc#1173247 and
  jsc#ECO-2006):

  - CVE-2020-11017: Fixed a double free which could have denied the server's
  service.

  - CVE-2020-11018: Fixed an out of bounds read which a malicious clients
  could have triggered.

  - CVE-2020-11019: Fixed an issue which could have led to denial of service
  if logger was set to 'WLOG_TRACE'.

  - CVE-2020-11038: Fixed a buffer overflow when /video redirection was used.

  - CVE-2020-11039: Fixed an issue which could have allowed arbitrary memory
  read and write when USB redirection was enabled.

  - CVE-2020-11040: Fixed an out of bounds data read in
  clear_decompress_subcode_rlex.

  - CVE-2020-11041: Fixed an issue with the configuration for sound backend
  which could have led to server's denial of service.

  - CVE-2020-11043: Fixed an out of bounds read in
  rfx_process_message_tileset.

  - CVE-2020-11085: Fixed an out of bounds read in cliprdr_read_format_list.

  - CVE-2020-11086: Fixed an out of bounds read in
  ntlm_read_ntlm_v2_client_challenge.

  - CVE-2020-11087: Fixed an out of bounds read in
  ntlm_read_AuthenticateMessage.

  - CVE-2020-11088: Fixed an out of bounds read in
  ntlm_read_NegotiateMessage.

  - CVE-2020-11089: Fixed an out of bounds read in irp function family.

  - CVE-2020-11095: Fixed a global out of bounds read in
  update_recv_primary_order.

  - CVE-2020-11096: Fixed a global out of bounds read in
  update_read_cache_bitmap_v3_order.

  - CVE-2020-11097: Fixed an out of bounds read in ntlm_av_pair_get.

  - CVE-2020-11098: Fixed an out of bounds read in glyph_cache_put.

  - CVE-2020-11099: Fixed an out of bounds Read in
  license_read_new_or_upgrade_license_packet.

  - CVE-2020-11521: Fixed an out of bounds write in planar.c (bsc#1171443).

  - CVE-2020-11522: Fixed an out of bounds read in gdi.c (bsc#1171444).

  - CVE-2020-11523: Fixed an integer overflow in region.c (bsc#1171445).

  - CVE-2020-11524: Fixed an out of bounds write in interleaved.c
  (bsc#1171446).

  - CVE-2020-11525: Fixed an out of bounds read in bitmap.c (bsc#1171447).

  - CVE-2020-11526: Fixed an out of bounds read in
  update_recv_secondary_order (bsc#1171674).

  - CVE-2020-13396: Fixed an Read in ntlm_read_ChallengeMessage.

  - CVE-2020-13397: Fixed an out of bounds read in security_fips_decrypt due
  to uninitialized value.

  - CVE-2020-13398: Fixed an out of bounds write in crypto_rsa_common.

  - CVE-2020-4030: Fixed an out of bounds read in `TrioParse`.

  - CVE-2020-4031: Fixed a use after free in gdi_SelectObject.

  - CVE-2020-4032: Fixed an int ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'freerdp' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland-debuginfo", rpm:"freerdp-wayland-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0-debuginfo", rpm:"libuwac0-0-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.1.2~lp151.5.6.1", rls:"openSUSELeap15.1"))) {
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