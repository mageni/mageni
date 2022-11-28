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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4167.1");
  script_cve_id("CVE-2022-42898");
  script_tag(name:"creation_date", value:"2022-11-23 00:15:45 +0000 (Wed, 23 Nov 2022)");
  script_version("2022-11-23T00:15:45+0000");
  script_tag(name:"last_modification", value:"2022-11-23 00:15:45 +0000 (Wed, 23 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4167-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4167-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224167-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the SUSE-SU-2022:4167-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for krb5 fixes the following issues:

CVE-2022-42898: Fixed integer overflow in PAC parsing (bsc#1205126).");

  script_tag(name:"affected", value:"'krb5' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Server Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-32bit-debuginfo", rpm:"krb5-32bit-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-client-debuginfo", rpm:"krb5-client-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp", rpm:"krb5-plugin-preauth-otp~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-otp-debuginfo", rpm:"krb5-plugin-preauth-otp-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit", rpm:"krb5-plugin-preauth-pkinit~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-pkinit-debuginfo", rpm:"krb5-plugin-preauth-pkinit-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-spake", rpm:"krb5-plugin-preauth-spake~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-preauth-spake-debuginfo", rpm:"krb5-plugin-preauth-spake-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap", rpm:"krb5-plugin-kdb-ldap~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-plugin-kdb-ldap-debuginfo", rpm:"krb5-plugin-kdb-ldap-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.19.2~150300.7.7.1", rls:"SLES15.0SP3"))) {
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
