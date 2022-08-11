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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14753.1");
  script_cve_id("CVE-2021-31607");
  script_tag(name:"creation_date", value:"2021-06-23 06:40:31 +0000 (Wed, 23 Jun 2021)");
  script_version("2021-06-23T06:40:31+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 20:24:00 +0000 (Tue, 04 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14753-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14753-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114753-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2021:14753-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

golang-github-wrouesnel-postgres_exporter:

Add support for aarch64

mgr-cfg:

SPEC: Updated Python definitions for RHEL8 and quoted text comparisons.

mgr-custom-info:

Update package version to 4.2.0

mgr-daemon:

Update translation strings

Update the translations from weblate

Added quotes around %{_vendor} token for the if statements in spec file.

Fix removal of mgr-deamon with selinux enabled (bsc#1177928)

Updating translations from weblate

mgr-osad:

Change the log file permissions as expected by logrotate (bsc#1177884)

Change deprecated path /var/run into /run for systemd (bsc#1185178)

Python fixes

Removal of RHEL5

mgr-push:

Defined __python for python2.

Excluded RHEL8 for Python 2 build.

mgr-virtualization:

Update package version to 4.2.0

rhnlib:

Update package version to 4.2.0

salt:

Prevent command injection in the snapper module (bsc#1185281)
 (CVE-2021-31607)

spacecmd:

Rename system migration to system transfer

Rename SP to product migration

Update translation strings

Add group_addconfigchannel and group_removeconfigchannel

Add group_listconfigchannels and configchannel_listgroups

Fix spacecmd compat with Python 3

Deprecated 'Software Crashes' feature

Document advanced package search on '--help' (bsc#1180583)

Fixed advanced search on 'package_listinstalledsystems'

Fixed duplicate results when using multiple search criteria (bsc#1180585)

Fixed 'non-advanced' package search when using multiple package names
 (bsc#1180584)

Update translations

Fix: make spacecmd build on Debian

Add Service Pack migration operations (bsc#1173557)

spacewalk-client-tools:

Update the translations from weblate

Drop the --noSSLServerURL option

Updated RHEL Python requirements.

Added quotes around %{_vendor}.

spacewalk-koan:

Fix for spacewalk-koan test

spacewalk-oscap:

Update package version to 4.2.0

spacewalk-remote-utils:

Update package version to 4.2.0

supportutils-plugin-susemanager-client:

Update package version to 4.2.0

suseRegisterInfo:

Add support for Amazon Linux 2

Add support for Alibaba Cloud Linux 2

Adapted for RHEL build.

uyuni-base:
Added Apache as prerequisite for RHEL and Fedora (due to required users).

Removed RHEL specific folder rights from SPEC file.

Added RHEL8 compatibility.

uyuni-common-libs:

Cleaning up unused Python 2 build leftovers.

Disabled debug package build.");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11-SP3");

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

if(release == "SLES11.0SP4") {
  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-custom-info", rpm:"mgr-custom-info~4.2.1~5.9.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.2.7~5.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.5~5.27.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-push", rpm:"mgr-push~4.2.2~5.9.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.2.1~5.17.3", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.2.2~5.15.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.5~5.27.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.5~5.27.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-push", rpm:"python2-mgr-push~4.2.2~5.9.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.2.1~5.17.3", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.2.1~5.17.3", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.3~12.31.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.10~27.50.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.10~27.50.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.10~27.50.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-koan", rpm:"python2-spacewalk-koan~4.2.3~9.21.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-oscap", rpm:"python2-spacewalk-oscap~4.2.1~6.15.3", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-suseRegisterInfo", rpm:"python2-suseRegisterInfo~4.2.3~6.15.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-uyuni-common-libs", rpm:"python2-uyuni-common-libs~4.2.3~5.12.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~43.75.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~43.75.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~43.75.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.8~18.84.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.10~27.50.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.10~27.50.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.10~27.50.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-koan", rpm:"spacewalk-koan~4.2.3~9.21.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-oscap", rpm:"spacewalk-oscap~4.2.1~6.15.3", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suseRegisterInfo", rpm:"suseRegisterInfo~4.2.3~6.15.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-wrouesnel-postgres_exporter", rpm:"golang-github-wrouesnel-postgres_exporter~0.4.7~5.12.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-remote-utils", rpm:"spacewalk-remote-utils~4.2.1~6.18.2", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.2.2~9.21.1", rls:"SLES11.0SP4"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-custom-info", rpm:"mgr-custom-info~4.2.1~5.9.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.2.7~5.26.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.5~5.27.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-push", rpm:"mgr-push~4.2.2~5.9.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.2.1~5.17.3", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.2.2~5.15.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.5~5.27.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.5~5.27.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-push", rpm:"python2-mgr-push~4.2.2~5.9.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.2.1~5.17.3", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.2.1~5.17.3", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.3~12.31.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.10~27.50.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.10~27.50.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.10~27.50.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-koan", rpm:"python2-spacewalk-koan~4.2.3~9.21.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-oscap", rpm:"python2-spacewalk-oscap~4.2.1~6.15.3", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-suseRegisterInfo", rpm:"python2-suseRegisterInfo~4.2.3~6.15.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-uyuni-common-libs", rpm:"python2-uyuni-common-libs~4.2.3~5.12.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~43.75.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~43.75.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~43.75.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.8~18.84.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.10~27.50.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.10~27.50.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.10~27.50.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-koan", rpm:"spacewalk-koan~4.2.3~9.21.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-oscap", rpm:"spacewalk-oscap~4.2.1~6.15.3", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suseRegisterInfo", rpm:"suseRegisterInfo~4.2.3~6.15.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-wrouesnel-postgres_exporter", rpm:"golang-github-wrouesnel-postgres_exporter~0.4.7~5.12.1", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-remote-utils", rpm:"spacewalk-remote-utils~4.2.1~6.18.2", rls:"SLES11.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.2.2~9.21.1", rls:"SLES11.0SP3"))){
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
