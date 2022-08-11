# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852833");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-5163", "CVE-2019-5164");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:34:24 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for shadowsocks-libev openSUSE-SU-2019:2667-1 (shadowsocks-libev)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shadowsocks-libev'
  package(s) announced via the openSUSE-SU-2019:2667_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shadowsocks-libev fixes the following issues:

  - Update version to 3.3.3

  * Refine the handling of suspicious connections.

  * Fix exploitable denial-of-service vulnerability exists in the UDPRelay
  functionality (boo#1158251, CVE-2019-5163)

  * Fix code execution vulnerability in the ss-manager binary
  (boo#1158365, CVE-2019-5164)

  * Refine the handling of fragment request.

  * Fix a high CPU bug introduced in 3.3.0. (#2449)

  * Enlarge the socket buffer size to 16KB.

  * Fix the empty list bug in ss-manager.

  * Fix the IPv6 address parser.

  * Fix a bug of port parser.

  * Fix a crash with MinGW.

  * Refine SIP003 plugin interface.

  * Remove connection timeout from all clients.

  * Fix the alignment bug again.

  * Fix a bug on 32-bit arch.

  * Add TCP fast open support to ss-tunnel by @PantherJohn.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2667=1");

  script_tag(name:"affected", value:"'shadowsocks-libev' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libshadowsocks-libev2", rpm:"libshadowsocks-libev2~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libshadowsocks-libev2-debuginfo", rpm:"libshadowsocks-libev2-debuginfo~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadowsocks-libev", rpm:"shadowsocks-libev~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadowsocks-libev-debuginfo", rpm:"shadowsocks-libev-debuginfo~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadowsocks-libev-debugsource", rpm:"shadowsocks-libev-debugsource~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadowsocks-libev-devel", rpm:"shadowsocks-libev-devel~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadowsocks-libev-doc", rpm:"shadowsocks-libev-doc~3.3.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
