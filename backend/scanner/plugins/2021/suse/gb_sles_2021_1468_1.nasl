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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1468.1");
  script_cve_id("CVE-2021-25214", "CVE-2021-25215");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:39+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 09:15:00 +0000 (Fri, 21 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1468-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211468-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2021:1468-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

CVE-2021-25214: Fixed a broken inbound incremental zone update (IXFR)
 which could have caused named to terminate unexpectedly (bsc#1185345).

CVE-2021-25215: Fixed an assertion check which could have failed while
 answering queries for DNAME records that required the DNAME to be
 processed to resolve itself (bsc#1185345).

MD5 warning message using host, dig, nslookup (bind-utils) on SLES 12
 SP5 with FIPS enabled (bsc#1181495).");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE OpenStack Cloud Crowbar 9, SUSE OpenStack Cloud 9, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server 12-SP4");

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

if(release == "SLES12.0SP5") {
  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161", rpm:"libbind9-161~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161-debuginfo", rpm:"libbind9-161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110", rpm:"libdns1110~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110-debuginfo", rpm:"libdns1110-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161", rpm:"libirs161~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161-debuginfo", rpm:"libirs161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107", rpm:"libisc1107~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo", rpm:"libisc1107-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161", rpm:"libisccc161~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161-debuginfo", rpm:"libisccc161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163", rpm:"libisccfg163~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163-debuginfo", rpm:"libisccfg163-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161", rpm:"liblwres161~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161-debuginfo", rpm:"liblwres161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-32bit", rpm:"libisc1107-32bit~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo-32bit", rpm:"libisc1107-debuginfo-32bit~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-bind", rpm:"python-bind~9.11.22~3.34.1", rls:"SLES12.0SP5"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {
  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161", rpm:"libbind9-161~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-161-debuginfo", rpm:"libbind9-161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110", rpm:"libdns1110~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1110-debuginfo", rpm:"libdns1110-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161", rpm:"libirs161~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs161-debuginfo", rpm:"libirs161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107", rpm:"libisc1107~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo", rpm:"libisc1107-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161", rpm:"libisccc161~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc161-debuginfo", rpm:"libisccc161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163", rpm:"libisccfg163~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg163-debuginfo", rpm:"libisccfg163-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161", rpm:"liblwres161~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres161-debuginfo", rpm:"liblwres161-debuginfo~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-32bit", rpm:"libisc1107-32bit~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1107-debuginfo-32bit", rpm:"libisc1107-debuginfo-32bit~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-bind", rpm:"python-bind~9.11.22~3.34.1", rls:"SLES12.0SP4"))){
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
