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
  script_oid("1.3.6.1.4.1.25623.1.0.853960");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2021-20286");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:05:52 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for kubevirt (openSUSE-SU-2021:2274-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2274-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BNYSQCMH37A42AG5LXPHSQQ6STSS3ZPT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubevirt'
  package(s) announced via the openSUSE-SU-2021:2274-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubevirt fixes the following issues:

     General:

  - Updated kubevirt to version 0.40.0

  - Fixed an issue when calling virsh-domcapabilities


     Security fixes:

  - CVE-2021-20286: A flaw was found in libnbd 1.7.3. An assertion failure
       in nbd_unlocked_opt_go in ilb/opt.c may lead to denial of service.");

  script_tag(name:"affected", value:"'kubevirt' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-container-disk", rpm:"kubevirt-container-disk~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-container-disk-debuginfo", rpm:"kubevirt-container-disk-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-manifests", rpm:"kubevirt-manifests~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-tests", rpm:"kubevirt-tests~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-tests-debuginfo", rpm:"kubevirt-tests-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-api", rpm:"kubevirt-virt-api~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-api-debuginfo", rpm:"kubevirt-virt-api-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-controller", rpm:"kubevirt-virt-controller~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-controller-debuginfo", rpm:"kubevirt-virt-controller-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-handler", rpm:"kubevirt-virt-handler~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-handler-debuginfo", rpm:"kubevirt-virt-handler-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-launcher", rpm:"kubevirt-virt-launcher~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-launcher-debuginfo", rpm:"kubevirt-virt-launcher-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-operator", rpm:"kubevirt-virt-operator~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virt-operator-debuginfo", rpm:"kubevirt-virt-operator-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl", rpm:"kubevirt-virtctl~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubevirt-virtctl-debuginfo", rpm:"kubevirt-virtctl-debuginfo~0.40.0~5.11.2", rls:"openSUSELeap15.3"))) {
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
