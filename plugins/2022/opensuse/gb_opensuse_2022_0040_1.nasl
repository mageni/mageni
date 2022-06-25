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
  script_oid("1.3.6.1.4.1.25623.1.0.854417");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-43565");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:36:30 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for kubevirt, (openSUSE-SU-2022:0040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0040-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PH3Q2TLVW235XFTNU2563GON62BFYPLP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubevirt, '
  package(s) announced via the openSUSE-SU-2022:0040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubevirt, virt-api-container, virt-controller-container,
     virt-handler-container, virt-launcher-container, virt-operator-container
     fixes the following issues:

  - CVE-2021-43565: Fixes a vulnerability in the golang.org/x/crypto/ssh
       package which allowed unauthenticated clients to cause a panic in SSH
       servers. (bsc#1193930)");

  script_tag(name:"affected", value:"'kubevirt, ' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-container-disk", rpm:"kubevirt-container-disk~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-container-disk-debuginfo", rpm:"kubevirt-container-disk-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-manifests", rpm:"kubevirt-manifests~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-tests", rpm:"kubevirt-tests~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-tests-debuginfo", rpm:"kubevirt-tests-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-api", rpm:"kubevirt-virt-api~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-api-debuginfo", rpm:"kubevirt-virt-api-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-controller", rpm:"kubevirt-virt-controller~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-controller-debuginfo", rpm:"kubevirt-virt-controller-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-handler", rpm:"kubevirt-virt-handler~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-handler-debuginfo", rpm:"kubevirt-virt-handler-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-launcher", rpm:"kubevirt-virt-launcher~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-launcher-debuginfo", rpm:"kubevirt-virt-launcher-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-operator", rpm:"kubevirt-virt-operator~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-operator-debuginfo", rpm:"kubevirt-virt-operator-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl", rpm:"kubevirt-virtctl~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl-debuginfo", rpm:"kubevirt-virtctl-debuginfo~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-kubevirt_containers_meta", rpm:"obs-service-kubevirt_containers_meta~0.45.0~8.7.1", rls:"openSUSELeap15.3"))) {
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