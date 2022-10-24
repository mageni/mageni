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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3650.1");
  script_cve_id("CVE-2022-26305", "CVE-2022-26307", "CVE-2022-3140");
  script_tag(name:"creation_date", value:"2022-10-19 04:54:17 +0000 (Wed, 19 Oct 2022)");
  script_version("2022-10-19T04:54:17+0000");
  script_tag(name:"last_modification", value:"2022-10-19 04:54:17 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-02 13:39:00 +0000 (Tue, 02 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3650-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3650-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223650-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the SUSE-SU-2022:3650-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libreoffice fixes the following issues:

 Updated to version 7.3.6.2 (jsc#SLE-23447):

 - CVE-2022-3140: Fixed macro URL arbitrary script execution
 (bsc#1203209).
 - CVE-2022-26305: Fixed execution of untrusted Macros due to improper
 certificate validation (bsc#1201868).
 - CVE-2022-26307: Fixed weak Master Keys in password storage
 (bsc#1201872).");

  script_tag(name:"affected", value:"'libreoffice' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base", rpm:"libreoffice-base~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-debuginfo", rpm:"libreoffice-base-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql", rpm:"libreoffice-base-drivers-postgresql~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql-debuginfo", rpm:"libreoffice-base-drivers-postgresql-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-branding-upstream", rpm:"libreoffice-branding-upstream~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc", rpm:"libreoffice-calc~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc-debuginfo", rpm:"libreoffice-calc-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc-extensions", rpm:"libreoffice-calc-extensions~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-debuginfo", rpm:"libreoffice-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-debugsource", rpm:"libreoffice-debugsource~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw", rpm:"libreoffice-draw~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw-debuginfo", rpm:"libreoffice-draw-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-filters-optional", rpm:"libreoffice-filters-optional~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gdb-pretty-printers", rpm:"libreoffice-gdb-pretty-printers~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-glade", rpm:"libreoffice-glade~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gnome", rpm:"libreoffice-gnome~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gnome-debuginfo", rpm:"libreoffice-gnome-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3", rpm:"libreoffice-gtk3~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3-debuginfo", rpm:"libreoffice-gtk3-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-icon-themes", rpm:"libreoffice-icon-themes~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress", rpm:"libreoffice-impress~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress-debuginfo", rpm:"libreoffice-impress-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-af", rpm:"libreoffice-l10n-af~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-am", rpm:"libreoffice-l10n-am~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ar", rpm:"libreoffice-l10n-ar~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-as", rpm:"libreoffice-l10n-as~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ast", rpm:"libreoffice-l10n-ast~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-be", rpm:"libreoffice-l10n-be~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bg", rpm:"libreoffice-l10n-bg~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bn", rpm:"libreoffice-l10n-bn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bn_IN", rpm:"libreoffice-l10n-bn_IN~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bo", rpm:"libreoffice-l10n-bo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-br", rpm:"libreoffice-l10n-br~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-brx", rpm:"libreoffice-l10n-brx~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bs", rpm:"libreoffice-l10n-bs~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ca", rpm:"libreoffice-l10n-ca~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ca_valencia", rpm:"libreoffice-l10n-ca_valencia~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ckb", rpm:"libreoffice-l10n-ckb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-cs", rpm:"libreoffice-l10n-cs~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-cy", rpm:"libreoffice-l10n-cy~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-da", rpm:"libreoffice-l10n-da~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-de", rpm:"libreoffice-l10n-de~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dgo", rpm:"libreoffice-l10n-dgo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dsb", rpm:"libreoffice-l10n-dsb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dz", rpm:"libreoffice-l10n-dz~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-el", rpm:"libreoffice-l10n-el~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en", rpm:"libreoffice-l10n-en~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en_GB", rpm:"libreoffice-l10n-en_GB~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en_ZA", rpm:"libreoffice-l10n-en_ZA~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-eo", rpm:"libreoffice-l10n-eo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-es", rpm:"libreoffice-l10n-es~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-et", rpm:"libreoffice-l10n-et~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-eu", rpm:"libreoffice-l10n-eu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fa", rpm:"libreoffice-l10n-fa~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fi", rpm:"libreoffice-l10n-fi~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fr", rpm:"libreoffice-l10n-fr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fur", rpm:"libreoffice-l10n-fur~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fy", rpm:"libreoffice-l10n-fy~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ga", rpm:"libreoffice-l10n-ga~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gd", rpm:"libreoffice-l10n-gd~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gl", rpm:"libreoffice-l10n-gl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gu", rpm:"libreoffice-l10n-gu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gug", rpm:"libreoffice-l10n-gug~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-he", rpm:"libreoffice-l10n-he~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hi", rpm:"libreoffice-l10n-hi~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hr", rpm:"libreoffice-l10n-hr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hsb", rpm:"libreoffice-l10n-hsb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hu", rpm:"libreoffice-l10n-hu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-id", rpm:"libreoffice-l10n-id~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-is", rpm:"libreoffice-l10n-is~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-it", rpm:"libreoffice-l10n-it~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ja", rpm:"libreoffice-l10n-ja~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ka", rpm:"libreoffice-l10n-ka~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kab", rpm:"libreoffice-l10n-kab~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kk", rpm:"libreoffice-l10n-kk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-km", rpm:"libreoffice-l10n-km~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kmr_Latn", rpm:"libreoffice-l10n-kmr_Latn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kn", rpm:"libreoffice-l10n-kn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ko", rpm:"libreoffice-l10n-ko~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kok", rpm:"libreoffice-l10n-kok~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ks", rpm:"libreoffice-l10n-ks~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lb", rpm:"libreoffice-l10n-lb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lo", rpm:"libreoffice-l10n-lo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lt", rpm:"libreoffice-l10n-lt~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lv", rpm:"libreoffice-l10n-lv~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mai", rpm:"libreoffice-l10n-mai~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mk", rpm:"libreoffice-l10n-mk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ml", rpm:"libreoffice-l10n-ml~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mn", rpm:"libreoffice-l10n-mn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mni", rpm:"libreoffice-l10n-mni~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mr", rpm:"libreoffice-l10n-mr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-my", rpm:"libreoffice-l10n-my~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nb", rpm:"libreoffice-l10n-nb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ne", rpm:"libreoffice-l10n-ne~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nl", rpm:"libreoffice-l10n-nl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nn", rpm:"libreoffice-l10n-nn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nr", rpm:"libreoffice-l10n-nr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nso", rpm:"libreoffice-l10n-nso~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-oc", rpm:"libreoffice-l10n-oc~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-om", rpm:"libreoffice-l10n-om~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-or", rpm:"libreoffice-l10n-or~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pa", rpm:"libreoffice-l10n-pa~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pl", rpm:"libreoffice-l10n-pl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pt_BR", rpm:"libreoffice-l10n-pt_BR~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pt_PT", rpm:"libreoffice-l10n-pt_PT~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ro", rpm:"libreoffice-l10n-ro~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ru", rpm:"libreoffice-l10n-ru~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-rw", rpm:"libreoffice-l10n-rw~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sa_IN", rpm:"libreoffice-l10n-sa_IN~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sat", rpm:"libreoffice-l10n-sat~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sd", rpm:"libreoffice-l10n-sd~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-si", rpm:"libreoffice-l10n-si~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sid", rpm:"libreoffice-l10n-sid~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sk", rpm:"libreoffice-l10n-sk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sl", rpm:"libreoffice-l10n-sl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sq", rpm:"libreoffice-l10n-sq~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sr", rpm:"libreoffice-l10n-sr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ss", rpm:"libreoffice-l10n-ss~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-st", rpm:"libreoffice-l10n-st~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sv", rpm:"libreoffice-l10n-sv~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sw_TZ", rpm:"libreoffice-l10n-sw_TZ~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-szl", rpm:"libreoffice-l10n-szl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ta", rpm:"libreoffice-l10n-ta~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-te", rpm:"libreoffice-l10n-te~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tg", rpm:"libreoffice-l10n-tg~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-th", rpm:"libreoffice-l10n-th~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tn", rpm:"libreoffice-l10n-tn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tr", rpm:"libreoffice-l10n-tr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ts", rpm:"libreoffice-l10n-ts~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tt", rpm:"libreoffice-l10n-tt~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ug", rpm:"libreoffice-l10n-ug~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-uk", rpm:"libreoffice-l10n-uk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-uz", rpm:"libreoffice-l10n-uz~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ve", rpm:"libreoffice-l10n-ve~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-vec", rpm:"libreoffice-l10n-vec~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-vi", rpm:"libreoffice-l10n-vi~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-xh", rpm:"libreoffice-l10n-xh~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zh_CN", rpm:"libreoffice-l10n-zh_CN~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zh_TW", rpm:"libreoffice-l10n-zh_TW~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zu", rpm:"libreoffice-l10n-zu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-librelogo", rpm:"libreoffice-librelogo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-mailmerge", rpm:"libreoffice-mailmerge~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math", rpm:"libreoffice-math~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math-debuginfo", rpm:"libreoffice-math-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean", rpm:"libreoffice-officebean~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean-debuginfo", rpm:"libreoffice-officebean-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno", rpm:"libreoffice-pyuno~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno-debuginfo", rpm:"libreoffice-pyuno-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-qt5", rpm:"libreoffice-qt5~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-qt5-debuginfo", rpm:"libreoffice-qt5-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk", rpm:"libreoffice-sdk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-debuginfo", rpm:"libreoffice-sdk-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-doc", rpm:"libreoffice-sdk-doc~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer", rpm:"libreoffice-writer~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer-debuginfo", rpm:"libreoffice-writer-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer-extensions", rpm:"libreoffice-writer-extensions~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit", rpm:"libreofficekit~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit-devel", rpm:"libreofficekit-devel~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base", rpm:"libreoffice-base~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-debuginfo", rpm:"libreoffice-base-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql", rpm:"libreoffice-base-drivers-postgresql~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql-debuginfo", rpm:"libreoffice-base-drivers-postgresql-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-branding-upstream", rpm:"libreoffice-branding-upstream~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc", rpm:"libreoffice-calc~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc-debuginfo", rpm:"libreoffice-calc-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc-extensions", rpm:"libreoffice-calc-extensions~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-debuginfo", rpm:"libreoffice-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-debugsource", rpm:"libreoffice-debugsource~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw", rpm:"libreoffice-draw~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw-debuginfo", rpm:"libreoffice-draw-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-filters-optional", rpm:"libreoffice-filters-optional~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gdb-pretty-printers", rpm:"libreoffice-gdb-pretty-printers~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-glade", rpm:"libreoffice-glade~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gnome", rpm:"libreoffice-gnome~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gnome-debuginfo", rpm:"libreoffice-gnome-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3", rpm:"libreoffice-gtk3~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3-debuginfo", rpm:"libreoffice-gtk3-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-icon-themes", rpm:"libreoffice-icon-themes~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress", rpm:"libreoffice-impress~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress-debuginfo", rpm:"libreoffice-impress-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-af", rpm:"libreoffice-l10n-af~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-am", rpm:"libreoffice-l10n-am~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ar", rpm:"libreoffice-l10n-ar~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-as", rpm:"libreoffice-l10n-as~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ast", rpm:"libreoffice-l10n-ast~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-be", rpm:"libreoffice-l10n-be~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bg", rpm:"libreoffice-l10n-bg~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bn", rpm:"libreoffice-l10n-bn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bn_IN", rpm:"libreoffice-l10n-bn_IN~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bo", rpm:"libreoffice-l10n-bo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-br", rpm:"libreoffice-l10n-br~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-brx", rpm:"libreoffice-l10n-brx~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-bs", rpm:"libreoffice-l10n-bs~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ca", rpm:"libreoffice-l10n-ca~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ca_valencia", rpm:"libreoffice-l10n-ca_valencia~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ckb", rpm:"libreoffice-l10n-ckb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-cs", rpm:"libreoffice-l10n-cs~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-cy", rpm:"libreoffice-l10n-cy~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-da", rpm:"libreoffice-l10n-da~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-de", rpm:"libreoffice-l10n-de~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dgo", rpm:"libreoffice-l10n-dgo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dsb", rpm:"libreoffice-l10n-dsb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-dz", rpm:"libreoffice-l10n-dz~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-el", rpm:"libreoffice-l10n-el~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en", rpm:"libreoffice-l10n-en~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en_GB", rpm:"libreoffice-l10n-en_GB~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-en_ZA", rpm:"libreoffice-l10n-en_ZA~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-eo", rpm:"libreoffice-l10n-eo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-es", rpm:"libreoffice-l10n-es~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-et", rpm:"libreoffice-l10n-et~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-eu", rpm:"libreoffice-l10n-eu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fa", rpm:"libreoffice-l10n-fa~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fi", rpm:"libreoffice-l10n-fi~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fr", rpm:"libreoffice-l10n-fr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fur", rpm:"libreoffice-l10n-fur~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-fy", rpm:"libreoffice-l10n-fy~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ga", rpm:"libreoffice-l10n-ga~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gd", rpm:"libreoffice-l10n-gd~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gl", rpm:"libreoffice-l10n-gl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gu", rpm:"libreoffice-l10n-gu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-gug", rpm:"libreoffice-l10n-gug~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-he", rpm:"libreoffice-l10n-he~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hi", rpm:"libreoffice-l10n-hi~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hr", rpm:"libreoffice-l10n-hr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hsb", rpm:"libreoffice-l10n-hsb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-hu", rpm:"libreoffice-l10n-hu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-id", rpm:"libreoffice-l10n-id~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-is", rpm:"libreoffice-l10n-is~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-it", rpm:"libreoffice-l10n-it~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ja", rpm:"libreoffice-l10n-ja~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ka", rpm:"libreoffice-l10n-ka~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kab", rpm:"libreoffice-l10n-kab~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kk", rpm:"libreoffice-l10n-kk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-km", rpm:"libreoffice-l10n-km~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kmr_Latn", rpm:"libreoffice-l10n-kmr_Latn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kn", rpm:"libreoffice-l10n-kn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ko", rpm:"libreoffice-l10n-ko~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-kok", rpm:"libreoffice-l10n-kok~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ks", rpm:"libreoffice-l10n-ks~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lb", rpm:"libreoffice-l10n-lb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lo", rpm:"libreoffice-l10n-lo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lt", rpm:"libreoffice-l10n-lt~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-lv", rpm:"libreoffice-l10n-lv~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mai", rpm:"libreoffice-l10n-mai~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mk", rpm:"libreoffice-l10n-mk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ml", rpm:"libreoffice-l10n-ml~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mn", rpm:"libreoffice-l10n-mn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mni", rpm:"libreoffice-l10n-mni~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-mr", rpm:"libreoffice-l10n-mr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-my", rpm:"libreoffice-l10n-my~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nb", rpm:"libreoffice-l10n-nb~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ne", rpm:"libreoffice-l10n-ne~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nl", rpm:"libreoffice-l10n-nl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nn", rpm:"libreoffice-l10n-nn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nr", rpm:"libreoffice-l10n-nr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-nso", rpm:"libreoffice-l10n-nso~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-oc", rpm:"libreoffice-l10n-oc~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-om", rpm:"libreoffice-l10n-om~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-or", rpm:"libreoffice-l10n-or~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pa", rpm:"libreoffice-l10n-pa~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pl", rpm:"libreoffice-l10n-pl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pt_BR", rpm:"libreoffice-l10n-pt_BR~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-pt_PT", rpm:"libreoffice-l10n-pt_PT~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ro", rpm:"libreoffice-l10n-ro~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ru", rpm:"libreoffice-l10n-ru~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-rw", rpm:"libreoffice-l10n-rw~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sa_IN", rpm:"libreoffice-l10n-sa_IN~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sat", rpm:"libreoffice-l10n-sat~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sd", rpm:"libreoffice-l10n-sd~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-si", rpm:"libreoffice-l10n-si~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sid", rpm:"libreoffice-l10n-sid~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sk", rpm:"libreoffice-l10n-sk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sl", rpm:"libreoffice-l10n-sl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sq", rpm:"libreoffice-l10n-sq~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sr", rpm:"libreoffice-l10n-sr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ss", rpm:"libreoffice-l10n-ss~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-st", rpm:"libreoffice-l10n-st~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sv", rpm:"libreoffice-l10n-sv~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-sw_TZ", rpm:"libreoffice-l10n-sw_TZ~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-szl", rpm:"libreoffice-l10n-szl~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ta", rpm:"libreoffice-l10n-ta~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-te", rpm:"libreoffice-l10n-te~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tg", rpm:"libreoffice-l10n-tg~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-th", rpm:"libreoffice-l10n-th~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tn", rpm:"libreoffice-l10n-tn~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tr", rpm:"libreoffice-l10n-tr~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ts", rpm:"libreoffice-l10n-ts~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-tt", rpm:"libreoffice-l10n-tt~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ug", rpm:"libreoffice-l10n-ug~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-uk", rpm:"libreoffice-l10n-uk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-uz", rpm:"libreoffice-l10n-uz~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-ve", rpm:"libreoffice-l10n-ve~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-vec", rpm:"libreoffice-l10n-vec~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-vi", rpm:"libreoffice-l10n-vi~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-xh", rpm:"libreoffice-l10n-xh~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zh_CN", rpm:"libreoffice-l10n-zh_CN~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zh_TW", rpm:"libreoffice-l10n-zh_TW~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-l10n-zu", rpm:"libreoffice-l10n-zu~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-librelogo", rpm:"libreoffice-librelogo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-mailmerge", rpm:"libreoffice-mailmerge~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math", rpm:"libreoffice-math~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math-debuginfo", rpm:"libreoffice-math-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean", rpm:"libreoffice-officebean~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean-debuginfo", rpm:"libreoffice-officebean-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno", rpm:"libreoffice-pyuno~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno-debuginfo", rpm:"libreoffice-pyuno-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-qt5", rpm:"libreoffice-qt5~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-qt5-debuginfo", rpm:"libreoffice-qt5-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk", rpm:"libreoffice-sdk~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-debuginfo", rpm:"libreoffice-sdk-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-doc", rpm:"libreoffice-sdk-doc~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer", rpm:"libreoffice-writer~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer-debuginfo", rpm:"libreoffice-writer-debuginfo~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer-extensions", rpm:"libreoffice-writer-extensions~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit", rpm:"libreofficekit~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit-devel", rpm:"libreofficekit-devel~7.3.6.2~150300.14.22.24.2", rls:"SLES15.0SP4"))) {
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
