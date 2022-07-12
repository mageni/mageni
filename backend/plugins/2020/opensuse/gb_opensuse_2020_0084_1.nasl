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
  script_oid("1.3.6.1.4.1.25623.1.0.852992");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2019-5068");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:17:18 +0000 (Mon, 27 Jan 2020)");
  script_name("openSUSE: Security Advisory for Mesa (openSUSE-SU-2020:0084_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00037.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mesa'
  package(s) announced via the openSUSE-SU-2020:0084_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Mesa fixes the following issues:

  Security issue fixed:

  - CVE-2019-5068: Fixed exploitable shared memory permissions vulnerability
  (bsc#1156015).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-84=1");

  script_tag(name:"affected", value:"'Mesa' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"Mesa", rpm:"Mesa~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-KHR-devel", rpm:"Mesa-KHR-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-debugsource", rpm:"Mesa-debugsource~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-devel", rpm:"Mesa-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri", rpm:"Mesa-dri~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-debuginfo", rpm:"Mesa-dri-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-devel", rpm:"Mesa-dri-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau", rpm:"Mesa-dri-nouveau~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-debuginfo", rpm:"Mesa-dri-nouveau-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-drivers-debugsource", rpm:"Mesa-drivers-debugsource~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium", rpm:"Mesa-gallium~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-debuginfo", rpm:"Mesa-gallium-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL-devel", rpm:"Mesa-libEGL-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1", rpm:"Mesa-libEGL1~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-debuginfo", rpm:"Mesa-libEGL1-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL-devel", rpm:"Mesa-libGL-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1", rpm:"Mesa-libGL1~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-debuginfo", rpm:"Mesa-libGL1-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel", rpm:"Mesa-libGLESv1_CM-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM1", rpm:"Mesa-libGLESv1_CM1~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-2", rpm:"Mesa-libGLESv2-2~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-devel", rpm:"Mesa-libGLESv2-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv3-devel", rpm:"Mesa-libGLESv3-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libOpenCL", rpm:"Mesa-libOpenCL~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libOpenCL-debuginfo", rpm:"Mesa-libOpenCL-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libVulkan-devel", rpm:"Mesa-libVulkan-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d", rpm:"Mesa-libd3d~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-debuginfo", rpm:"Mesa-libd3d-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel", rpm:"Mesa-libd3d-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel", rpm:"Mesa-libglapi-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0", rpm:"Mesa-libglapi0~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-debuginfo", rpm:"Mesa-libglapi0-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libva", rpm:"Mesa-libva~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libva-debuginfo", rpm:"Mesa-libva-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel", rpm:"libOSMesa-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8", rpm:"libOSMesa8~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-debuginfo", rpm:"libOSMesa8-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau", rpm:"libXvMC_nouveau~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-debuginfo", rpm:"libXvMC_nouveau-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600", rpm:"libXvMC_r600~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-debuginfo", rpm:"libXvMC_r600-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel", rpm:"libgbm-devel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-debuginfo", rpm:"libgbm1-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau", rpm:"libvdpau_nouveau~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-debuginfo", rpm:"libvdpau_nouveau-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300", rpm:"libvdpau_r300~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-debuginfo", rpm:"libvdpau_r300-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600", rpm:"libvdpau_r600~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-debuginfo", rpm:"libvdpau_r600-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi", rpm:"libvdpau_radeonsi~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-debuginfo", rpm:"libvdpau_radeonsi-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel", rpm:"libvulkan_intel~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-debuginfo", rpm:"libvulkan_intel-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon", rpm:"libvulkan_radeon~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-debuginfo", rpm:"libvulkan_radeon-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker-devel", rpm:"libxatracker-devel~1.0.0~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2", rpm:"libxatracker2~1.0.0~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2-debuginfo", rpm:"libxatracker2-debuginfo~1.0.0~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-32bit", rpm:"Mesa-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-32bit", rpm:"Mesa-dri-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-32bit-debuginfo", rpm:"Mesa-dri-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-32bit", rpm:"Mesa-dri-nouveau-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-32bit-debuginfo", rpm:"Mesa-dri-nouveau-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-32bit", rpm:"Mesa-gallium-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-32bit-debuginfo", rpm:"Mesa-gallium-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit", rpm:"Mesa-libEGL1-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit-debuginfo", rpm:"Mesa-libEGL1-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit", rpm:"Mesa-libGL1-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit-debuginfo", rpm:"Mesa-libGL1-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-32bit", rpm:"Mesa-libd3d-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-32bit-debuginfo", rpm:"Mesa-libd3d-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel-32bit", rpm:"Mesa-libd3d-devel-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel-32bit", rpm:"Mesa-libglapi-devel-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit", rpm:"Mesa-libglapi0-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit-debuginfo", rpm:"Mesa-libglapi0-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel-32bit", rpm:"libOSMesa-devel-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-32bit", rpm:"libOSMesa8-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-32bit-debuginfo", rpm:"libOSMesa8-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-32bit", rpm:"libXvMC_nouveau-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-32bit-debuginfo", rpm:"libXvMC_nouveau-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-32bit", rpm:"libXvMC_r600-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-32bit-debuginfo", rpm:"libXvMC_r600-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel-32bit", rpm:"libgbm-devel-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit", rpm:"libgbm1-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit-debuginfo", rpm:"libgbm1-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-32bit", rpm:"libvdpau_nouveau-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-32bit-debuginfo", rpm:"libvdpau_nouveau-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-32bit", rpm:"libvdpau_r300-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-32bit-debuginfo", rpm:"libvdpau_r300-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-32bit", rpm:"libvdpau_r600-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-32bit-debuginfo", rpm:"libvdpau_r600-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-32bit", rpm:"libvdpau_radeonsi-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-32bit-debuginfo", rpm:"libvdpau_radeonsi-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-32bit", rpm:"libvulkan_intel-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-32bit-debuginfo", rpm:"libvulkan_intel-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-32bit", rpm:"libvulkan_radeon-32bit~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-32bit-debuginfo", rpm:"libvulkan_radeon-32bit-debuginfo~18.3.2~lp151.23.9.1", rls:"openSUSELeap15.1"))) {
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