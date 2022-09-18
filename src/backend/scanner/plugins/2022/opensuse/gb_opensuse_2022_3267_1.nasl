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
  script_oid("1.3.6.1.4.1.25623.1.0.854984");
  script_version("2022-09-16T08:42:26+0000");
  script_cve_id("CVE-2021-39360");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-16 08:42:26 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 18:56:00 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2022-09-15 01:02:13 +0000 (Thu, 15 Sep 2022)");
  script_name("openSUSE: Security Advisory for libzapojit (SUSE-SU-2022:3267-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3267-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FWCMYGUHRZQMXRHO2E7YMQLB5KO6AOKS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzapojit'
  package(s) announced via the SUSE-SU-2022:3267-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzapojit fixes the following issues:

  - CVE-2021-39360: Fixed missing guard against invalid SSL certificates
       (bsc#1189844).");

  script_tag(name:"affected", value:"'libzapojit' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzapojit-0_0-0", rpm:"libzapojit-0_0-0~0.0.3~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzapojit-0_0-0-debuginfo", rpm:"libzapojit-0_0-0-debuginfo~0.0.3~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzapojit-debugsource", rpm:"libzapojit-debugsource~0.0.3~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzapojit-devel", rpm:"libzapojit-devel~0.0.3~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Zpj-0_0", rpm:"typelib-1_0-Zpj-0_0~0.0.3~150000.3.5.1", rls:"openSUSELeap15.3"))) {
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