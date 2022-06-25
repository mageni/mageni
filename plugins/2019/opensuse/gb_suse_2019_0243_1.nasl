# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852316");
  script_version("2019-04-02T06:16:35+0000");
  script_cve_id("CVE-2019-3814");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-04-02 06:16:35 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-26 04:11:58 +0100 (Tue, 26 Feb 2019)");
  script_name("SuSE Update for dovecot23 openSUSE-SU-2019:0243-1 (dovecot23)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00062.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot23'
  package(s) announced via the openSUSE-SU-2019:0243_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot23 fixes the following issues:

  dovecot was updated to 2.3.3 release, bringing lots of bugfixes
  (bsc#1124356).

  Also the following security issue was fixed:

  - CVE-2019-3814: A vulnerability in Dovecot related to SSL client
  certificate authentication  was fixed (bsc#1123022)

  The package changes:

  Updated pigeonhole to 0.5.3:

  - Fix assertion panic occurring when managesieve service fails to
  open INBOX while saving a Sieve script. This was caused by a lack of
  cleanup after failure.

  - Fix specific messages causing an assert panic with actions that compose
  a reply (e.g. vacation). With some rather weird input from the original
  message, the header folding algorithm (as used for composing the
  References header for the reply) got confused, causing the panic.

  - IMAP FILTER=SIEVE capability: Fix FILTER SIEVE SCRIPT command parsing.
  After finishing reading the Sieve script, the command parsing sometimes
  didn't continue with the search arguments. This is a time- critical bug
  that likely only occurs when the Sieve script is sent in the next TCP
  frame.

  dovecot23 was updated to 2.3.3:

  - doveconf hides more secrets now in the default output.

  - ssl_dh setting is no longer enforced at startup. If it's not set and
  non-ECC DH key exchange happens, error is logged and client is
  disconnected.

  - Added log_debug= filter  setting.

  - Added log_core_filter= log filter  setting.

  - quota-clone: Write to dict asynchronously

  - --enable-hardening attempts to use retpoline Spectre 2 mitigations

  - lmtp proxy: Support source_ip passdb extra field.

  - doveadm stats dump: Support more fields and output stddev by default.

  - push-notification: Add SSL support for OX backend.

  - NUL bytes in mail headers can cause truncated replies when fetched.

  - director: Conflicting host up/down state changes may in some rare
  situations ended up in a loop of two directors constantly
  overwriting each others' changes.

  - director: Fix hang/crash when multiple doveadm commands are being
  handled concurrently.

  - director: Fix assert-crash if doveadm disconnects too early

  - virtual plugin: Some searches used 100% CPU for many seconds

  - dsync assert-crashed with acl plugin in some situations. (bsc#1119850)

  - mail_attachment_detection_options=add-flags-on-save assert-crashed with
  some specific Sieve scripts.

  - Mail snippet generation crashed with mails containing invalid
  Content-Type:multipart header.

  - Log prefix ordering was different for some log lines.

  - quota: With noenforcing option current quota usage wasn't updated.

  - ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"dovecot23 on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"dovecot23", rpm:"dovecot23~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-backend-mysql", rpm:"dovecot23-backend-mysql~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-backend-mysql-debuginfo", rpm:"dovecot23-backend-mysql-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-backend-pgsql", rpm:"dovecot23-backend-pgsql~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-backend-pgsql-debuginfo", rpm:"dovecot23-backend-pgsql-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-backend-sqlite", rpm:"dovecot23-backend-sqlite~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-backend-sqlite-debuginfo", rpm:"dovecot23-backend-sqlite-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-debuginfo", rpm:"dovecot23-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-debugsource", rpm:"dovecot23-debugsource~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-devel", rpm:"dovecot23-devel~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts", rpm:"dovecot23-fts~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-debuginfo", rpm:"dovecot23-fts-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-lucene", rpm:"dovecot23-fts-lucene~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-lucene-debuginfo", rpm:"dovecot23-fts-lucene-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-solr", rpm:"dovecot23-fts-solr~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-solr-debuginfo", rpm:"dovecot23-fts-solr-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-squat", rpm:"dovecot23-fts-squat~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot23-fts-squat-debuginfo", rpm:"dovecot23-fts-squat-debuginfo~2.3.3~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
