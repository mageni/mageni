# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2097.1");
  script_cve_id("CVE-2021-42550");
  script_tag(name:"creation_date", value:"2023-05-04 09:52:17 +0000 (Thu, 04 May 2023)");
  script_version("2023-05-04T11:18:57+0000");
  script_tag(name:"last_modification", value:"2023-05-04 11:18:57 +0000 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-22 03:08:00 +0000 (Wed, 22 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2097-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2097-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232097-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maven and recommended update for antlr3, minlog, sbt, xmvn' package(s) announced via the SUSE-SU-2023:2097-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for antlr3, maven, minlog, sbt, xmvn fixes the following issues:
maven:

Version update from 3.8.5 to 3.8.6 (jsc#SLE-23217):
Security fixes:
CVE-2021-42550: Update Version of (optional) Logback (bsc#1193795)


Bug fixes:
Fix resolver session containing non-MavenWorkspaceReader Fix for multiple maven instances working on same source tree that can lock each other Don't ignore bin/ otherwise bin/ in apache-maven module cannot be added back Fix IllegalStateException in SessionScope during guice injection in multithreaded build Revert MNG-7347 (SessionScoped beans should be singletons for a given session)
Fix compilation failure with relocated transitive dependency Fix deadlock during forked lifecycle executions Fix issue with resolving dependencies between submodules


New features and improvements:
Create a multiline message helper for boxed log messages Display a warning when an aggregator mojo is locking other mojo executions Align Assembly Descriptor NS versions


Dependency upgrades:
Upgrade SLF4J to 1.7.36 Upgrade JUnit to 4.13.2 Upgrade Plexus Utils to 3.3.1


Move mvn.1 from bin to man directory

antlr3:

Bug fixes in this version update from 3.5.2 to 3.5.3 (jsc#SLE-23217):
Change source compatibility to 1.8 and enable github workflows Change Wiki URLs to theantlrguy.atlassian.net in README.txt Add Bazel support Remove enforcer plugin as it is not needed in a controlled environment

minlog:

Bug fixes in this version update from 1.3.0 to 1.3.1 (jsc#SLE-23217):
Use currentTimeMillis Use 3-Clause BSD
Use Java 7 JDK.

sbt:

Fix build issues with maven 3.8.6 (jsc#SLE-23217)

xmvn:

Remove RPM package build dependency on easymock (jsc#SLE-23217)");

  script_tag(name:"affected", value:"'maven and recommended update for antlr3, minlog, sbt, xmvn' package(s) on SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.8.6~150200.4.9.8", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.8.6~150200.4.9.8", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minlog", rpm:"minlog~1.3.1~150200.3.7.8", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.0.0~150200.3.7.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.0.0~150200.3.7.8", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.0.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.8.6~150200.4.9.8", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.8.6~150200.4.9.8", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minlog", rpm:"minlog~1.3.1~150200.3.7.8", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.0.0~150200.3.7.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.0.0~150200.3.7.8", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.0.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
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
