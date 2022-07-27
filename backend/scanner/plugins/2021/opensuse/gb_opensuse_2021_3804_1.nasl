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
  script_oid("1.3.6.1.4.1.25623.1.0.854321");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2019-20005", "CVE-2019-20006", "CVE-2019-20007", "CVE-2019-20198", "CVE-2019-20199", "CVE-2019-20200", "CVE-2019-20201", "CVE-2019-20202", "CVE-2021-26220", "CVE-2021-26221", "CVE-2021-26222", "CVE-2021-30485", "CVE-2021-31229", "CVE-2021-31347", "CVE-2021-31348", "CVE-2021-31598");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-26 02:01:55 +0000 (Fri, 26 Nov 2021)");
  script_name("openSUSE: Security Advisory for netcdf (openSUSE-SU-2021:3804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3804-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DM4S3HXSBD3QQY6J6J2S4KVWTO63OS7U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netcdf'
  package(s) announced via the openSUSE-SU-2021:3804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netcdf fixes the following issues:

  - Fixed multiple vulnerabilities in ezXML: CVE-2019-20007, CVE-2019-20006,
       CVE-2019-20201, CVE-2019-20202, CVE-2019-20199, CVE-2019-20200,
       CVE-2019-20198, CVE-2021-26221, CVE-2021-26222, CVE-2021-30485,
       CVE-2021-31229, CVE-2021-31347, CVE-2021-31348, CVE-2021-31598
       (bsc#1191856)");
  script_tag(name:"affected", value:"'netcdf' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13", rpm:"libnetcdf13~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-debuginfo", rpm:"libnetcdf13-debuginfo~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-openmpi", rpm:"libnetcdf13-openmpi~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-openmpi-debuginfo", rpm:"libnetcdf13-openmpi-debuginfo~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi", rpm:"netcdf-openmpi~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi-debuginfo", rpm:"netcdf-openmpi-debuginfo~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi-devel", rpm:"netcdf-openmpi-devel~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi-devel-data", rpm:"netcdf-openmpi-devel-data~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi-devel-debuginfo", rpm:"netcdf-openmpi-devel-debuginfo~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi-devel-static", rpm:"netcdf-openmpi-devel-static~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-32bit", rpm:"libnetcdf13-32bit~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-32bit-debuginfo", rpm:"libnetcdf13-32bit-debuginfo~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-openmpi-32bit", rpm:"libnetcdf13-openmpi-32bit~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf13-openmpi-32bit-debuginfo", rpm:"libnetcdf13-openmpi-32bit-debuginfo~4.6.1~5.7.1", rls:"openSUSELeap15.3"))) {
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
