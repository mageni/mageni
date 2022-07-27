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
  script_oid("1.3.6.1.4.1.25623.1.0.853355");
  script_version("2020-08-14T06:59:33+0000");
  script_cve_id("CVE-2020-15652", "CVE-2020-15653", "CVE-2020-15654", "CVE-2020-15655", "CVE-2020-15656", "CVE-2020-15657", "CVE-2020-15658", "CVE-2020-15659", "CVE-2020-6463", "CVE-2020-6514");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-14 09:58:14 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-13 03:01:00 +0000 (Thu, 13 Aug 2020)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2020:1189-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1189-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00025.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the openSUSE-SU-2020:1189-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  This update for MozillaFirefox and pipewire fixes the following issues:

  MozillaFirefox Extended Support Release 78.1.0 ESR

  * Fixed: Various stability, functionality, and security fixes (bsc#1174538)

  * CVE-2020-15652: Potential leak of redirect targets when loading scripts
  in a worker

  * CVE-2020-6514: WebRTC data channel leaks internal address to peer

  * CVE-2020-15655: Extension APIs could be used to bypass Same-Origin Policy

  * CVE-2020-15653: Bypassing iframe sandbox when allowing popups

  * CVE-2020-6463: Use-after-free in ANGLE
  gl::Texture::onUnbindAsSamplerTexture

  * CVE-2020-15656: Type confusion for special arguments in IonMonkey

  * CVE-2020-15658: Overriding file type when saving to disk

  * CVE-2020-15657: DLL hijacking due to incorrect loading path

  * CVE-2020-15654: Custom cursor can overlay user interface

  * CVE-2020-15659: Memory safety bugs fixed in Firefox 79 and Firefox ESR
  78.1

  pipewire was updated to version 0.3.6 (bsc#1171433, jsc#ECO-2308):

  * Extensive memory leak fixing and stress testing was done. A big leak in
  screen sharing with DMA-BUF was fixed.

  * Compile fixes

  * Stability improvements in jack and pulseaudio layers.

  * Added the old portal module to make the Camera portal work again. This
  will be moved to the session manager in future versions.

  * Improvements to the GStreamer source and sink shutdown.

  * Fix compatibility with v2 clients again when negotiating buffers.


  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1189=1");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~78.1.0~lp152.2.15.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire", rpm:"gstreamer-plugin-pipewire~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire-debuginfo", rpm:"gstreamer-plugin-pipewire-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0", rpm:"libpipewire-0_3-0~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-debuginfo", rpm:"libpipewire-0_3-0-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire", rpm:"pipewire~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-debuginfo", rpm:"pipewire-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-debugsource", rpm:"pipewire-debugsource~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-devel", rpm:"pipewire-devel~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-doc", rpm:"pipewire-doc~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3", rpm:"pipewire-libjack-0_3~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-debuginfo", rpm:"pipewire-libjack-0_3-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libpulse-0_3", rpm:"pipewire-libpulse-0_3~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libpulse-0_3-debuginfo", rpm:"pipewire-libpulse-0_3-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules", rpm:"pipewire-modules~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-debuginfo", rpm:"pipewire-modules-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2", rpm:"pipewire-spa-plugins-0_2~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-debuginfo", rpm:"pipewire-spa-plugins-0_2-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools", rpm:"pipewire-spa-tools~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools-debuginfo", rpm:"pipewire-spa-tools-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools", rpm:"pipewire-tools~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools-debuginfo", rpm:"pipewire-tools-debuginfo~0.3.6~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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