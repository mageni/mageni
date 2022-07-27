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
  script_oid("1.3.6.1.4.1.25623.1.0.854646");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2021-29509", "CVE-2021-41136", "CVE-2022-23634");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-24 19:30:00 +0000 (Mon, 24 May 2021)");
  script_tag(name:"creation_date", value:"2022-05-17 12:07:10 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for rubygem-puma (SUSE-SU-2022:1515-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1515-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4FVSP2SFD2BB42ZDWXSP7S7353LK4HVU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-puma'
  package(s) announced via the SUSE-SU-2022:1515-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-puma fixes the following issues:
  rubygem-puma was updated to version 4.3.11:

  * CVE-2021-29509: Adjusted an incomplete fix for  allows Denial of Service
       (DoS) (bsc#1188527)

  * CVE-2021-41136: Fixed request smuggling if HTTP header value contains
       the LF character (bsc#1191681)

  * CVE-2022-23634: Fixed information leak between requests (bsc#1196222)");

  script_tag(name:"affected", value:"'rubygem-puma' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma", rpm:"ruby2.5-rubygem-puma~4.3.11~150000.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma-debuginfo", rpm:"ruby2.5-rubygem-puma-debuginfo~4.3.11~150000.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma-doc", rpm:"ruby2.5-rubygem-puma-doc~4.3.11~150000.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-puma-debugsource", rpm:"rubygem-puma-debugsource~4.3.11~150000.3.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma", rpm:"ruby2.5-rubygem-puma~4.3.11~150000.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma-debuginfo", rpm:"ruby2.5-rubygem-puma-debuginfo~4.3.11~150000.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma-doc", rpm:"ruby2.5-rubygem-puma-doc~4.3.11~150000.3.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-puma-debugsource", rpm:"rubygem-puma-debugsource~4.3.11~150000.3.6.2", rls:"openSUSELeap15.3"))) {
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