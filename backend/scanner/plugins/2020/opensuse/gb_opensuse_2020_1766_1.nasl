# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853530");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-15190", "CVE-2020-15191", "CVE-2020-15192", "CVE-2020-15193", "CVE-2020-15194", "CVE-2020-15195", "CVE-2020-15202", "CVE-2020-15203", "CVE-2020-15204", "CVE-2020-15205", "CVE-2020-15206", "CVE-2020-15207", "CVE-2020-15208", "CVE-2020-15209", "CVE-2020-15210", "CVE-2020-15211");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-30 04:01:00 +0000 (Fri, 30 Oct 2020)");
  script_name("openSUSE: Security Advisory for tensorflow2 (openSUSE-SU-2020:1766-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1766-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tensorflow2'
  package(s) announced via the openSUSE-SU-2020:1766-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tensorflow2 fixes the following issues:

  - updated to 2.1.2 with following fixes (boo#1177022):

  * Fixes an undefined behavior causing a segfault in tf.raw_ops.Switch
  (CVE-2020-15190)

  * Fixes three vulnerabilities in conversion to DLPack format
  (CVE-2020-15191, CVE-2020-15192, CVE-2020-15193)

  * Fixes two vulnerabilities in SparseFillEmptyRowsGrad (CVE-2020-15194,
  CVE-2020-15195)

  * Fixes an integer truncation vulnerability in code using the work
  sharder API (CVE-2020-15202)

  * Fixes a format string vulnerability in tf.strings.as_string
  (CVE-2020-15203)

  * Fixes segfault raised by calling session-only ops in eager mode
  (CVE-2020-15204)

  * Fixes data leak and potential ASLR violation from
  tf.raw_ops.StringNGrams (CVE-2020-15205)

  * Fixes segfaults caused by incomplete SavedModel validation
  (CVE-2020-15206)

  * Fixes a data corruption due to a bug in negative indexing support in
  TFLite (CVE-2020-15207)

  * Fixes a data corruption due to dimension mismatch in TFLite
  (CVE-2020-15208)

  * Fixes several vulnerabilities in TFLite saved model format
  (CVE-2020-15209, CVE-2020-15210, CVE-2020-15211)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1766=1");

  script_tag(name:"affected", value:"'tensorflow2' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow2", rpm:"libtensorflow2~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow2-debuginfo", rpm:"libtensorflow2-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow2-gnu-hpc", rpm:"libtensorflow2-gnu-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow2-gnu-hpc-debuginfo", rpm:"libtensorflow2-gnu-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow2-gnu-openmpi2-hpc", rpm:"libtensorflow2-gnu-openmpi2-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow2-gnu-openmpi2-hpc-debuginfo", rpm:"libtensorflow2-gnu-openmpi2-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_cc2", rpm:"libtensorflow_cc2~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_cc2-debuginfo", rpm:"libtensorflow_cc2-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_cc2-gnu-hpc", rpm:"libtensorflow_cc2-gnu-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_cc2-gnu-hpc-debuginfo", rpm:"libtensorflow_cc2-gnu-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_cc2-gnu-openmpi2-hpc", rpm:"libtensorflow_cc2-gnu-openmpi2-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_cc2-gnu-openmpi2-hpc-debuginfo", rpm:"libtensorflow_cc2-gnu-openmpi2-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_framework2", rpm:"libtensorflow_framework2~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_framework2-debuginfo", rpm:"libtensorflow_framework2-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_framework2-gnu-hpc", rpm:"libtensorflow_framework2-gnu-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_framework2-gnu-hpc-debuginfo", rpm:"libtensorflow_framework2-gnu-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_framework2-gnu-openmpi2-hpc", rpm:"libtensorflow_framework2-gnu-openmpi2-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtensorflow_framework2-gnu-openmpi2-hpc-debuginfo", rpm:"libtensorflow_framework2-gnu-openmpi2-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2", rpm:"tensorflow2~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-debuginfo", rpm:"tensorflow2-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-debugsource", rpm:"tensorflow2-debugsource~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-devel", rpm:"tensorflow2-devel~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-doc", rpm:"tensorflow2-doc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-gnu-hpc", rpm:"tensorflow2-gnu-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-gnu-openmpi2-hpc", rpm:"tensorflow2-gnu-openmpi2-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-lite", rpm:"tensorflow2-lite~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-lite-debuginfo", rpm:"tensorflow2-lite-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-lite-debugsource", rpm:"tensorflow2-lite-debugsource~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2-lite-devel", rpm:"tensorflow2-lite-devel~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-hpc", rpm:"tensorflow2_2_1_2-gnu-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-hpc-debuginfo", rpm:"tensorflow2_2_1_2-gnu-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-hpc-debugsource", rpm:"tensorflow2_2_1_2-gnu-hpc-debugsource~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-hpc-devel", rpm:"tensorflow2_2_1_2-gnu-hpc-devel~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-hpc-doc", rpm:"tensorflow2_2_1_2-gnu-hpc-doc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-openmpi2-hpc", rpm:"tensorflow2_2_1_2-gnu-openmpi2-hpc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-openmpi2-hpc-debuginfo", rpm:"tensorflow2_2_1_2-gnu-openmpi2-hpc-debuginfo~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-openmpi2-hpc-debugsource", rpm:"tensorflow2_2_1_2-gnu-openmpi2-hpc-debugsource~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-openmpi2-hpc-devel", rpm:"tensorflow2_2_1_2-gnu-openmpi2-hpc-devel~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tensorflow2_2_1_2-gnu-openmpi2-hpc-doc", rpm:"tensorflow2_2_1_2-gnu-openmpi2-hpc-doc~2.1.2~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
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