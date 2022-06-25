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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1498.1");
  script_cve_id("CVE-2020-27840", "CVE-2021-20254", "CVE-2021-20277");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:39+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1498-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1498-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211498-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2021:1498-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

CVE-2021-20277: Fixed an out of bounds read in ldb_handler_fold
 (bsc#1183574).

CVE-2021-20254: Fixed a buffer overrun in sids_to_unixids()
 (bsc#1184677).

CVE-2020-27840: Fixed an unauthenticated remote heap corruption via bad
 DNs (bsc#1183572).

Avoid free'ing our own pointer in memcache when memcache_trim attempts
 to reduce cache size (bsc#1179156).

s3-libads: use dns name to open a ldap session (bsc#1184310).

Adjust smbcacls '--propagate-inheritance' feature to align with upstream
 (bsc#1178469).");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Manager Server 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Proxy 4.0, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Availability 15-SP1, SUSE Enterprise Storage 6, SUSE CaaS Platform 4.0");

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
  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo", rpm:"libdcerpc-binding0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-devel", rpm:"libdcerpc-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr-devel", rpm:"libdcerpc-samr-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0", rpm:"libdcerpc-samr0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0-debuginfo", rpm:"libdcerpc-samr0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo", rpm:"libdcerpc0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-devel", rpm:"libndr-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac-devel", rpm:"libndr-krb5pac-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo", rpm:"libndr-krb5pac0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt-devel", rpm:"libndr-nbt-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo", rpm:"libndr-nbt0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard-devel", rpm:"libndr-standard-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo", rpm:"libndr-standard0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo", rpm:"libndr0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo", rpm:"libnetapi0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials-devel", rpm:"libsamba-credentials-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo", rpm:"libsamba-credentials0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors-devel", rpm:"libsamba-errors-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0", rpm:"libsamba-errors0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-debuginfo", rpm:"libsamba-errors0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig-devel", rpm:"libsamba-hostconfig-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo", rpm:"libsamba-hostconfig0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb-devel", rpm:"libsamba-passdb-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0", rpm:"libsamba-passdb0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-debuginfo", rpm:"libsamba-passdb0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0", rpm:"libsamba-policy0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo", rpm:"libsamba-policy0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util-devel", rpm:"libsamba-util-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo", rpm:"libsamba-util0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb-devel", rpm:"libsamdb-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo", rpm:"libsamdb0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo", rpm:"libsmbclient0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf-devel", rpm:"libsmbconf-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo", rpm:"libsmbconf0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap-devel", rpm:"libsmbldap-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2", rpm:"libsmbldap2~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-debuginfo", rpm:"libsmbldap2-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util-devel", rpm:"libtevent-util-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo", rpm:"libtevent-util0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo", rpm:"libwbclient0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc", rpm:"samba-ad-dc~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-debuginfo", rpm:"samba-ad-dc-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-core-devel", rpm:"samba-core-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python", rpm:"samba-libs-python~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-debuginfo", rpm:"samba-libs-python-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python-debuginfo", rpm:"samba-python-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit-debuginfo", rpm:"libdcerpc-binding0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit-debuginfo", rpm:"libdcerpc0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit-debuginfo", rpm:"libndr-krb5pac0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit-debuginfo", rpm:"libndr-nbt0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit-debuginfo", rpm:"libndr-standard0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit-debuginfo", rpm:"libndr0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit-debuginfo", rpm:"libnetapi0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit-debuginfo", rpm:"libsamba-credentials0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit", rpm:"libsamba-errors0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit-debuginfo", rpm:"libsamba-errors0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit-debuginfo", rpm:"libsamba-hostconfig0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit", rpm:"libsamba-passdb0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit-debuginfo", rpm:"libsamba-passdb0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit-debuginfo", rpm:"libsamba-util0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit-debuginfo", rpm:"libsamdb0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit-debuginfo", rpm:"libsmbconf0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit", rpm:"libsmbldap2-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit-debuginfo", rpm:"libsmbldap2-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit-debuginfo", rpm:"libtevent-util0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit-debuginfo", rpm:"libwbclient0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit-debuginfo", rpm:"samba-winbind-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit", rpm:"libdcerpc-binding0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-32bit-debuginfo", rpm:"libdcerpc-binding0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0", rpm:"libdcerpc-binding0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-binding0-debuginfo", rpm:"libdcerpc-binding0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-devel", rpm:"libdcerpc-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr-devel", rpm:"libdcerpc-samr-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0", rpm:"libdcerpc-samr0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc-samr0-debuginfo", rpm:"libdcerpc-samr0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit", rpm:"libdcerpc0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-32bit-debuginfo", rpm:"libdcerpc0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0", rpm:"libdcerpc0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcerpc0-debuginfo", rpm:"libdcerpc0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-devel", rpm:"libndr-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac-devel", rpm:"libndr-krb5pac-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit", rpm:"libndr-krb5pac0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-32bit-debuginfo", rpm:"libndr-krb5pac0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0", rpm:"libndr-krb5pac0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-krb5pac0-debuginfo", rpm:"libndr-krb5pac0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt-devel", rpm:"libndr-nbt-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit", rpm:"libndr-nbt0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-32bit-debuginfo", rpm:"libndr-nbt0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0", rpm:"libndr-nbt0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-nbt0-debuginfo", rpm:"libndr-nbt0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard-devel", rpm:"libndr-standard-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit", rpm:"libndr-standard0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-32bit-debuginfo", rpm:"libndr-standard0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0", rpm:"libndr-standard0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr-standard0-debuginfo", rpm:"libndr-standard0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit", rpm:"libndr0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-32bit-debuginfo", rpm:"libndr0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0", rpm:"libndr0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndr0-debuginfo", rpm:"libndr0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit", rpm:"libnetapi0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-32bit-debuginfo", rpm:"libnetapi0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0-debuginfo", rpm:"libnetapi0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials-devel", rpm:"libsamba-credentials-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit", rpm:"libsamba-credentials0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-32bit-debuginfo", rpm:"libsamba-credentials0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0", rpm:"libsamba-credentials0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-credentials0-debuginfo", rpm:"libsamba-credentials0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors-devel", rpm:"libsamba-errors-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit", rpm:"libsamba-errors0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-32bit-debuginfo", rpm:"libsamba-errors0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0", rpm:"libsamba-errors0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-errors0-debuginfo", rpm:"libsamba-errors0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig-devel", rpm:"libsamba-hostconfig-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit", rpm:"libsamba-hostconfig0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-32bit-debuginfo", rpm:"libsamba-hostconfig0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0", rpm:"libsamba-hostconfig0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-hostconfig0-debuginfo", rpm:"libsamba-hostconfig0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb-devel", rpm:"libsamba-passdb-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit", rpm:"libsamba-passdb0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-32bit-debuginfo", rpm:"libsamba-passdb0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0", rpm:"libsamba-passdb0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-passdb0-debuginfo", rpm:"libsamba-passdb0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0", rpm:"libsamba-policy0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo", rpm:"libsamba-policy0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util-devel", rpm:"libsamba-util-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit", rpm:"libsamba-util0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-32bit-debuginfo", rpm:"libsamba-util0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0", rpm:"libsamba-util0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-util0-debuginfo", rpm:"libsamba-util0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb-devel", rpm:"libsamdb-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit", rpm:"libsamdb0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-32bit-debuginfo", rpm:"libsamdb0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0", rpm:"libsamdb0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamdb0-debuginfo", rpm:"libsamdb0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-debuginfo", rpm:"libsmbclient0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf-devel", rpm:"libsmbconf-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit", rpm:"libsmbconf0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-32bit-debuginfo", rpm:"libsmbconf0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0", rpm:"libsmbconf0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbconf0-debuginfo", rpm:"libsmbconf0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap-devel", rpm:"libsmbldap-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit", rpm:"libsmbldap2-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-32bit-debuginfo", rpm:"libsmbldap2-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2", rpm:"libsmbldap2~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbldap2-debuginfo", rpm:"libsmbldap2-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util-devel", rpm:"libtevent-util-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit", rpm:"libtevent-util0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-32bit-debuginfo", rpm:"libtevent-util0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0", rpm:"libtevent-util0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent-util0-debuginfo", rpm:"libtevent-util0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit", rpm:"libwbclient0-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-32bit-debuginfo", rpm:"libwbclient0-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0-debuginfo", rpm:"libwbclient0-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc", rpm:"samba-ad-dc~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-debuginfo", rpm:"samba-ad-dc-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-core-devel", rpm:"samba-core-devel~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python", rpm:"samba-libs-python~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-debuginfo", rpm:"samba-libs-python-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python-debuginfo", rpm:"samba-python-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit", rpm:"samba-winbind-32bit~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-32bit-debuginfo", rpm:"samba-winbind-32bit-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.9.5+git.432.d9b18c4f390~3.50.1", rls:"SLES15.0SP1"))){
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
