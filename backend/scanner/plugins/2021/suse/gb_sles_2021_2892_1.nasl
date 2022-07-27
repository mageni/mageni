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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2892.1");
  script_cve_id("CVE-2020-12100", "CVE-2020-24386", "CVE-2020-28200", "CVE-2021-29157", "CVE-2021-33515");
  script_tag(name:"creation_date", value:"2021-09-01 02:21:24 +0000 (Wed, 01 Sep 2021)");
  script_version("2021-09-01T02:21:24+0000");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-06 23:15:00 +0000 (Wed, 06 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2892-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212892-1/");
  script_xref(name:"URL", value:"https://doc.dovecot.org/settings/advanced/");
  script_xref(name:"URL", value:"https://doc.dovecot.org/settings/plugin/compress-plugin/");
  script_xref(name:"URL", value:"https://doc.dovecot.org/admin_manual/list_of_events/#indexer-worker-indexin");
  script_xref(name:"URL", value:"https://doc.dovecot.org/admin_manual/list_of_events/#mail");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot23' package(s) announced via the SUSE-SU-2021:2892-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot23 fixes the following issues:

Update dovecot to version 2.3.15 (jsc#SLE-19970):

Security issues fixed:

CVE-2021-29157: Dovecot does not correctly escape kid and azp fields in
 JWT tokens. This may be used to supply attacker controlled keys to
 validate tokens, if attacker has local access. (bsc#1187418) Local
 attacker can login as any user and access their emails

CVE-2021-33515: On-path attacker could have injected plaintext commands
 before STARTTLS negotiation that would be executed after STARTTLS
 finished with the client. (bsc#1187419) Attacker can potentially steal
 user credentials and mails

Disconnection log messages are now more standardized across services.
 They also always now start with 'Disconnected' prefix.

Dovecot now depends on libsystemd for systemd integration.

Removed support for Lua 5.2. Use version 5.1 or 5.3 instead.

config: Some settings are now marked as 'hidden'. It's discouraged to
 change these settings. They will no longer be visible in doveconf
 output, except if they have been changed or if doveconf -s parameter is
 used. See [link moved to references] for details.

imap-compress: Compression level is now algorithm specific. See
 [link moved to references]

indexer-worker: Convert 'Indexed' info logs to an event named
 'indexer_worker_indexing_finished'. See [link moved to references]
 g-finished

Add TSLv1.3 support to min_protocols.

Allow configuring ssl_cipher_suites. (for TLSv1.3+)

acl: Add acl_ignore_namespace setting which allows to entirely ignore
 ACLs for the listed namespaces.

imap: Support official RFC8970 preview/snippet syntax. Old methods of
 retrieving preview information via IMAP commands ('SNIPPET and PREVIEW
 with explicit algorithm selection') have been deprecated.

imapc: Support INDEXPVT for imapc storage to enable private message
 flags for cluster wide shared mailboxes.

lib-storage: Add new events: mail_opened, mail_expunge_requested,
 mail_expunged, mail_cache_lookup_finished. See
 [link moved to references]

zlib, imap-compression, fs-compress: Support compression levels that the
 algorithm supports. Before, we would allow hardcoded value between 1 to
 9 and would default to 6. Now we allow using per-algorithm value range
 and default to whatever default the algorithm specifies.

*-login: Commands pipelined together with and just after the
 authenticate command cause these commands to be executed twice. This
 applies to all protocols that involve user login, which currently
 comprises of imap, pop3, submisision and managesieve.

*-login: Processes are supposed to disconnect the oldest non-logged in
 connection when process_limit was reached. This didn't actually happen
 with the default 'high-security mode' (with service_count=1) where each
 connection is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dovecot23' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.15~58.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.15~58.3", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.15~58.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.15~58.3", rls:"SLES15.0SP3"))) {
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
