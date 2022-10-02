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
  script_oid("1.3.6.1.4.1.25623.1.0.822512");
  script_version("2022-09-26T10:10:50+0000");
  script_cve_id("CVE-2022-1996");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:00 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-09-23 01:02:16 +0000 (Fri, 23 Sep 2022)");
  script_name("openSUSE: Security Advisory for cdi-apiserver-container, (SUSE-SU-2022:3334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3334-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XBDPVYGY2ZBBXPF2AQGNYPQK2SQORIAQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cdi-apiserver-container, '
  package(s) announced via the SUSE-SU-2022:3334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cdi-apiserver-container, cdi-cloner-container,
     cdi-controller-container, cdi-importer-container, cdi-operator-container,
     cdi-uploadproxy-container, cdi-uploadserver-container,
     containerized-data-importer fixes the following issues:
  Update to version 1.51.0

  Security issues fixed in vendored dependencies:

  - CVE-2022-1996: Fixed CORS bypass (bsc#1200528)

  - Include additional tools used by cdi-importer: cdi-containerimage-server
       cdi-image-size-detection cdi-source-update-poller

  - Pack only cdi-operator and cdi-cr release manifests

  - Install tar for cloning filesystem PVCs");

  script_tag(name:"affected", value:"'cdi-apiserver-container, ' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-api", rpm:"containerized-data-importer-api~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-api-debuginfo", rpm:"containerized-data-importer-api-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-cloner", rpm:"containerized-data-importer-cloner~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-cloner-debuginfo", rpm:"containerized-data-importer-cloner-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-controller", rpm:"containerized-data-importer-controller~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-controller-debuginfo", rpm:"containerized-data-importer-controller-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-importer", rpm:"containerized-data-importer-importer~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-importer-debuginfo", rpm:"containerized-data-importer-importer-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-manifests", rpm:"containerized-data-importer-manifests~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-operator", rpm:"containerized-data-importer-operator~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-operator-debuginfo", rpm:"containerized-data-importer-operator-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-uploadproxy", rpm:"containerized-data-importer-uploadproxy~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-uploadproxy-debuginfo", rpm:"containerized-data-importer-uploadproxy-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-uploadserver", rpm:"containerized-data-importer-uploadserver~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerized-data-importer-uploadserver-debuginfo", rpm:"containerized-data-importer-uploadserver-debuginfo~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-cdi_containers_meta", rpm:"obs-service-cdi_containers_meta~1.51.0~150400.4.3.1", rls:"openSUSELeap15.4"))) {
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
