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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4488.1");
  script_cve_id("CVE-2022-2255");
  script_tag(name:"creation_date", value:"2022-12-15 04:18:54 +0000 (Thu, 15 Dec 2022)");
  script_version("2022-12-15T10:11:09+0000");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 16:14:00 +0000 (Wed, 31 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4488-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4488-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224488-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_wsgi' package(s) announced via the SUSE-SU-2022:4488-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_wsgi fixes the following issues:

CVE-2022-2255: Hardened the trusted proxy header filter to avoid bypass.
 (bsc#1201634)");

  script_tag(name:"affected", value:"'apache2-mod_wsgi' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1, SUSE Linux Enterprise Module for Public Cloud 15-SP2, SUSE Linux Enterprise Module for Public Cloud 15-SP3, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.1, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.2, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.3, SUSE Linux Enterprise Module for Server Applications 15-SP3, SUSE Linux Enterprise Module for Server Applications 15-SP4.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi", rpm:"apache2-mod_wsgi~4.5.18~150000.4.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-debuginfo", rpm:"apache2-mod_wsgi-debuginfo~4.5.18~150000.4.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-debugsource", rpm:"apache2-mod_wsgi-debugsource~4.5.18~150000.4.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi", rpm:"apache2-mod_wsgi~4.5.18~150000.4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-debuginfo", rpm:"apache2-mod_wsgi-debuginfo~4.5.18~150000.4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-debugsource", rpm:"apache2-mod_wsgi-debugsource~4.5.18~150000.4.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi", rpm:"apache2-mod_wsgi~4.5.18~150000.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-debuginfo", rpm:"apache2-mod_wsgi-debuginfo~4.5.18~150000.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-debugsource", rpm:"apache2-mod_wsgi-debugsource~4.5.18~150000.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-python3", rpm:"apache2-mod_wsgi-python3~4.5.18~150000.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-python3-debuginfo", rpm:"apache2-mod_wsgi-python3-debuginfo~4.5.18~150000.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-python3-debugsource", rpm:"apache2-mod_wsgi-python3-debugsource~4.5.18~150000.4.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-python3", rpm:"apache2-mod_wsgi-python3~4.5.18~150000.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-python3-debuginfo", rpm:"apache2-mod_wsgi-python3-debuginfo~4.5.18~150000.4.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_wsgi-python3-debugsource", rpm:"apache2-mod_wsgi-python3-debugsource~4.5.18~150000.4.6.1", rls:"SLES15.0SP4"))) {
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
