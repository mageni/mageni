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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0126.1");
  script_cve_id("CVE-2021-20251", "CVE-2022-37966", "CVE-2022-38023");
  script_tag(name:"creation_date", value:"2023-01-25 04:21:15 +0000 (Wed, 25 Jan 2023)");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 14:50:00 +0000 (Thu, 10 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0126-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230126-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2023:0126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

CVE-2021-20251: Fixed an issue where the bad password count would not be
 properly incremented, which could allow attackers to brute force a
 user's password (bsc#1206546).

CVE-2022-38023: Disabled weak ciphers by default in the Netlogon Secure
 channel (bsc#1206504).

CVE-2022-37966: Fixed an issue where a weak cipher would be selected to
 encrypt session keys, which could lead to privilege escalation
 (bsc#1205385).");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo-32bit", rpm:"libdcerpc-binding0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo", rpm:"libdcerpc-binding0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo-32bit", rpm:"libdcerpc0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo", rpm:"libdcerpc0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo-32bit", rpm:"libndr-krb5pac0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo", rpm:"libndr-krb5pac0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo-32bit", rpm:"libndr-nbt0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo", rpm:"libndr-nbt0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo-32bit", rpm:"libndr-standard0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo", rpm:"libndr-standard0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo-32bit", rpm:"libndr0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo", rpm:"libndr0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo-32bit", rpm:"libnetapi0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo", rpm:"libnetapi0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo-32bit", rpm:"libsamba-credentials0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo", rpm:"libsamba-credentials0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit", rpm:"libsamba-errors0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0", rpm:"libsamba-errors0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-debuginfo-32bit", rpm:"libsamba-errors0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-debuginfo", rpm:"libsamba-errors0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo-32bit", rpm:"libsamba-hostconfig0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo", rpm:"libsamba-hostconfig0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit", rpm:"libsamba-passdb0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0", rpm:"libsamba-passdb0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-debuginfo-32bit", rpm:"libsamba-passdb0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-debuginfo", rpm:"libsamba-passdb0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo-32bit", rpm:"libsamba-util0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo", rpm:"libsamba-util0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo-32bit", rpm:"libsamdb0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo", rpm:"libsamdb0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-32bit", rpm:"libsmbclient0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo-32bit", rpm:"libsmbclient0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo", rpm:"libsmbclient0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo-32bit", rpm:"libsmbconf0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo", rpm:"libsmbconf0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-32bit", rpm:"libsmbldap0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0", rpm:"libsmbldap0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-debuginfo-32bit", rpm:"libsmbldap0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap0-debuginfo", rpm:"libsmbldap0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo-32bit", rpm:"libtevent-util0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo", rpm:"libtevent-util0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo-32bit", rpm:"libwbclient0-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo", rpm:"libwbclient0-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo-32bit", rpm:"samba-client-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo-32bit", rpm:"samba-libs-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo-32bit", rpm:"samba-winbind-debuginfo-32bit~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.6.16+git.384.9fec958bed~3.76.1", rls:"SLES12.0SP4"))) {
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
