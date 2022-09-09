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
  script_oid("1.3.6.1.4.1.25623.1.0.854966");
  script_version("2022-09-09T08:44:16+0000");
  script_cve_id("CVE-2021-20178", "CVE-2021-20180", "CVE-2021-20191", "CVE-2021-20228", "CVE-2021-3447", "CVE-2021-3583", "CVE-2021-3620");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-09 08:44:16 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-03 20:43:00 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2022-09-09 01:01:41 +0000 (Fri, 09 Sep 2022)");
  script_name("openSUSE: Security Advisory for Important (SUSE-SU-2022:3178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3178-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DFWNQXR53TBUXTDTSJHWW3DNYZSUSUSF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Important'
  package(s) announced via the SUSE-SU-2022:3178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:
  ansible:

  - Update to version 2.9.27 (jsc#SLE-23631, jsc#SLE-24133)

  * CVE-2021-3620 ansible-connection module discloses sensitive info in
         traceback error message (in 2.9.27) (bsc#1187725)

  * CVE-2021-3583 Template Injection through yaml multi-line strings with
         ansible facts used in template. (in 2.9.23) (bsc#1188061)

  * ansible module nmcli is broken in ansible 2.9.13 (in 2.9.15)
         (bsc#1176460)

  - Update to 2.9.22:

  * CVE-2021-3447 (bsc#1183684) multiple modules expose secured values

  * CVE-2021-20228 (bsc#1181935) basic.py no_log with fallback option

  * CVE-2021-20191 (bsc#1181119) multiple collections exposes secured
         values

  * CVE-2021-20180 (bsc#1180942) bitbucket_pipeline_variable exposes
         sensitive values

  * CVE-2021-20178 (bsc#1180816) user data leak in snmp_facts module
  dracut-saltboot:

  - Require e2fsprogs (bsc#1202614)

  - Update to version 0.1.1657643023.0d694ce

  * Update dracut-saltboot dependencies (bsc#1200970)

  * Fix network loading when ipappend is used in pxe config

  * Add new information messages
  golang-github-QubitProducts-exporter_exporter:

  - Remove license file from %doc
  mgr-daemon:

  - Version 4.3.5-1

  * Update translation strings
  mgr-virtualization:

  - Version 4.3.6-1

  * Report all VMs in poller, not only running ones (bsc#1199528)
  prometheus-blackbox_exporter:

  - Exclude s390 arch
  python-hwdata:

  - Declare the LICENSE file as license and not doc
  spacecmd:

  - Version 4.3.14-1

  * Fix missing argument on system_listmigrationtargets (bsc#1201003)

  * Show correct help on calling kickstart_importjson with no arguments

  * Fix tracebacks on spacecmd kickstart_export (bsc#1200591)

  * Change proxy container config default filename to end with tar.gz

  * Update translation strings
  spacewalk-client-tools:

  - Version 4.3.11-1

  * Update translation strings
  uyuni-common-libs:

  - Version 4.3.5-1

  * Fix reposync issue about 'rpm.hdr' object has no attribute 'get'
  uyuni-proxy-systemd-services:

  - Version 4.3.6-1

  * Expose port 80 (bsc#1200142)

  * Use volumes rather than bind mounts

  * TFTPD to listen on udp port (bsc#1200968)

  * Add TAG variable in configuration

  * Fix containers namespaces in configuration
  zypp-plugin-spacewalk:

  - 1.0.13

  * Log in before listing channels. (bsc#1197963, bsc#1193585)");

  script_tag(name:"affected", value:"'Important' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prometheus-blackbox_exporter", rpm:"prometheus-blackbox_exporter~0.19.0~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wire", rpm:"wire~0.5.0~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wire-debuginfo", rpm:"wire-debuginfo~0.5.0~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.27~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-doc", rpm:"ansible-doc~2.9.27~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-test", rpm:"ansible-test~2.9.27~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~0.1.1657643023.0d694ce~150000.1.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hwdata", rpm:"python3-hwdata~2.3.5~150000.3.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.14~150000.3.83.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-QubitProducts-exporter_exporter", rpm:"golang-github-QubitProducts-exporter_exporter~0.4.0~150000.1.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.27~150000.1.14.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-doc", rpm:"ansible-doc~2.9.27~150000.1.14.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-test", rpm:"ansible-test~2.9.27~150000.1.14.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~0.1.1657643023.0d694ce~150000.1.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-hwdata", rpm:"python2-hwdata~2.3.5~150000.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hwdata", rpm:"python3-hwdata~2.3.5~150000.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.14~150000.3.83.1", rls:"openSUSELeap15.3"))) {
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