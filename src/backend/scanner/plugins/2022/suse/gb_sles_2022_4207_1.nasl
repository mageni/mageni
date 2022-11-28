# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4207.1");
  script_cve_id("CVE-2022-32888", "CVE-2022-32923", "CVE-2022-42799", "CVE-2022-42823", "CVE-2022-42824");
  script_tag(name:"creation_date", value:"2022-11-24 04:19:01 +0000 (Thu, 24 Nov 2022)");
  script_version("2022-11-24T10:18:54+0000");
  script_tag(name:"last_modification", value:"2022-11-24 10:18:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 12:49:00 +0000 (Thu, 03 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4207-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4207-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224207-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2022:4207-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fixes:

CVE-2022-32888: Fixed possible arbitrary code execution via maliciously
 crafted web content (bsc#1205121).

CVE-2022-32923: Fixed possible information leak via maliciously crafted
 web content (bsc#1205122).

CVE-2022-42799: Fixed user interface spoofing when visiting a malicious
 website (bsc#1205123).

CVE-2022-42823: Fixed possible arbitrary code execution via maliciously
 crafted web content (bsc#1205120).

CVE-2022-42824: Fixed possible sensitive user information leak via
 maliciously crafted web content (bsc#1205124).

Update to version 2.38.2:

 - Fix scrolling issues in some sites having fixed background.
 - Fix prolonged buffering during progressive live playback.
 - Fix the build with accessibility disabled.
 - Fix several crashes and rendering issues.

Update to version 2.38.1:

 - Make xdg-dbus-proxy work if host session bus address is an abstract
 socket.
 - Use a single xdg-dbus-proxy process when sandbox is enabled.
 - Fix high resolution video playback due to unimplemented changeType
 operation.
 - Ensure GSubprocess uses posix_spawn() again and inherit file
 descriptors.
 - Fix player stucking in buffering (paused) state for progressive
 streaming.
 - Do not try to preconnect on link click when link preconnect setting is
 disabled.
 - Fix close status code returned when the client closes a WebSocket in
 some cases.
 - Fix media player duration calculation.
 - Fix several crashes and rendering issues.

Update to version 2.38.0:

 - New media controls UI style.
 - Add new API to set WebView's Content-Security-Policy for web
 extensions support.
 - Make it possible to use the remote inspector from other browsers using
 WEBKIT_INSPECTOR_HTTP_SERVER env var.
 - MediaSession is enabled by default, allowing remote media control
 using MPRIS.
 - Add support for PDF documents using PDF.js.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Desktop Applications 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-debugsource", rpm:"webkit2gtk3-soup2-debugsource~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0", rpm:"libjavascriptcoregtk-4_1-0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0-debuginfo", rpm:"libjavascriptcoregtk-4_1-0-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0", rpm:"libwebkit2gtk-4_1-0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0-debuginfo", rpm:"libwebkit2gtk-4_1-0-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_1", rpm:"typelib-1_0-JavaScriptCore-4_1~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_1", rpm:"typelib-1_0-WebKit2-4_1~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_1", rpm:"typelib-1_0-WebKit2WebExtension-4_1~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles", rpm:"webkit2gtk-4_1-injected-bundles~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles-debuginfo", rpm:"webkit2gtk-4_1-injected-bundles-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-5_0-0", rpm:"libjavascriptcoregtk-5_0-0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-5_0-0-debuginfo", rpm:"libjavascriptcoregtk-5_0-0-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-5_0-0", rpm:"libwebkit2gtk-5_0-0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-5_0-0-debuginfo", rpm:"libwebkit2gtk-5_0-0-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-5_0", rpm:"typelib-1_0-JavaScriptCore-5_0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-5_0", rpm:"typelib-1_0-WebKit2-5_0~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-5_0-injected-bundles", rpm:"webkit2gtk-5_0-injected-bundles~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-5_0-injected-bundles-debuginfo", rpm:"webkit2gtk-5_0-injected-bundles-debuginfo~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-debugsource", rpm:"webkit2gtk4-debugsource~2.38.2~150400.4.22.1", rls:"SLES15.0SP4"))) {
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
