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
  script_oid("1.3.6.1.4.1.25623.1.0.854991");
  script_version("2022-09-20T10:11:40+0000");
  script_cve_id("CVE-2022-2850");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-17 01:02:44 +0000 (Sat, 17 Sep 2022)");
  script_name("openSUSE: Security Advisory for 389-ds (SUSE-SU-2022:3286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3286-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XZK7THO2O2WKEXIL24C4JFRGBWZTNTT7");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds'
  package(s) announced via the SUSE-SU-2022:3286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for 389-ds fixes the following issues:

  - CVE-2022-2850: Fixed an application crash when running a sync_repl
       client that could be triggered via a malformed cookie (bsc#1202470).
  Non-security fixes:

  - Update to version 2.0.16~git20.219f047ae:

  * Fix missing 'not' in description

  * CI - makes replication/acceptance_test.py::test_modify_entry more
         robust

  * fix repl keep alive event interval

  * Sync_repl may crash while managing invalid cookie

  * Hostname when set to localhost causing failures in other tests

  * lib389 - do not set backend name to lowercase

  * keep alive update event starts too soon

  * Fix various memory leaks

  * UI - LDAP Editor is not updated when we switch instances

  * Supplier should do periodic updates

  - Update sudoers schema to support UTF-8 (bsc#1197998)

  - Update to version 2.0.16~git9.e2a858a86:

  * UI - Various fixes and RFE's for UI

  * Remove problematic language from source code

  * CI - disable TLS hostname checking

  * Update npm and cargo packages

  * Support ECDSA private keys for TLS");

  script_tag(name:"affected", value:"'389-ds' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-2.0.16", rpm:"389-ds-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debuginfo-2.0.16", rpm:"389-ds-debuginfo-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-debugsource-2.0.16", rpm:"389-ds-debugsource-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-devel-2.0.16", rpm:"389-ds-devel-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-2.0.16", rpm:"389-ds-snmp-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-snmp-debuginfo-2.0.16", rpm:"389-ds-snmp-debuginfo-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-2.0.16", rpm:"lib389-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-2.0.16", rpm:"libsvrcore0-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvrcore0-debuginfo-2.0.16", rpm:"libsvrcore0-debuginfo-2.0.16~git20.219f047ae~150400.3.10.1", rls:"openSUSELeap15.4"))) {
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
