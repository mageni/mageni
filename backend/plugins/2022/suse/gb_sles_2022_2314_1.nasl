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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2314.1");
  script_cve_id("CVE-2022-24903");
  script_tag(name:"creation_date", value:"2022-07-08 04:33:24 +0000 (Fri, 08 Jul 2022)");
  script_version("2022-07-13T12:05:39+0000");
  script_tag(name:"last_modification", value:"2022-07-13 12:05:39 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 14:00:00 +0000 (Tue, 17 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2314-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222314-1/");
  script_xref(name:"URL", value:"https://github.com/rsyslog/rsyslog/issues/4598");
  script_xref(name:"URL", value:"https://github.com/rsyslog/rsyslog/issues/3727");
  script_xref(name:"URL", value:"https://github.com/rsyslog/rsyslog/issues/3727");
  script_xref(name:"URL", value:"https://github.com/rsyslog/rsyslog/issues/4429");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsyslog' package(s) announced via the SUSE-SU-2022:2314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsyslog fixes the following issues:

CVE-2022-24903: fix potential heap buffer overflow in modules for TCP
 syslog reception (bsc#1199061)

Upgrade to rsyslog 8.2106.0 (bsc#1188039)

 * NOTE: the prime new feature is support for TLS and non-TLS connections
 via imtcp in parallel. Furthermore, most TLS parameters can now be
 overridden at the input() level. The notable exceptions are certificate
 files, something that is due to be implemented as next step.
 * 2021-06-14: new global option 'parser.supportCompressionExtension'
 This permits to turn off rsyslog's single-message compression
 extension when it interferes with non-syslog message processing (the
 parser subsystem expects syslog messages, not generic text) closes
 [link moved to references]
 * 2021-05-12: imtcp: add more override config params to input() It is
 now possible to override all module parameters at the input() level.
 Module parameters serve as defaults. Existing configs need no
 modification.
 * 2021-05-06: imtcp: add stream driver parameter to input()
 configuration This permits to have different inputs use different
 stream drivers and stream driver parameters. closes
 [link moved to references]
 * 2021-04-29: imtcp: permit to run multiple inputs in parallel
 Previously, a single server was used to run all imtcp inputs. This had
 a couple of drawsbacks. First and foremost, we could not use different
 stream drivers in the varios inputs. This patch now provides a
 baseline to do that, but does still not implement the capability (in
 this sense it is a staging patch). Secondly, we now ensure that each
 input has at least one exclusive thread for processing, untangling the
 performance of multiple inputs from each other. see also:
 [link moved to references]
 * 2021-04-27: tcpsrv bugfix: potential sluggishnes and hang on shutdown
 tcpsrv is used by multiple other modules (imtcp, imdiag, imgssapi,
 and, in theory, also others - even ones we do not know about).
 However, the internal synchornization did not properly take multiple
 tcpsrv users in consideration. As such, a single user could hang under
 some circumstances. This was caused by improperly awaking all users
 from a pthread condition wait. That in turn could lead to some
 sluggish behaviour and, in rare cases, a hang at shutdown. Note: it
 was highly unlikely to experience real problems with the
 officially provided modules.
 * 2021-04-22: refactoring of syslog/tcp driver parameter passing This
 has now been generalized to a parameter block, which makes it much
 cleaner and also easier to add new parameters in the future.
 * 2021-04-22: config script: add re_match_i() and re_extract_i()
 functions This provides case-insensitive regex functionality. closes
 [link moved to references]

Update to rsyslog 8.2104.0:
 * rainerscript: call getgrnam_r ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'rsyslog' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debuginfo", rpm:"rsyslog-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debugsource", rpm:"rsyslog-debugsource~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-diag-tools", rpm:"rsyslog-diag-tools~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-diag-tools-debuginfo", rpm:"rsyslog-diag-tools-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-doc", rpm:"rsyslog-doc~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gssapi", rpm:"rsyslog-module-gssapi~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gssapi-debuginfo", rpm:"rsyslog-module-gssapi-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gtls", rpm:"rsyslog-module-gtls~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gtls-debuginfo", rpm:"rsyslog-module-gtls-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mmnormalize", rpm:"rsyslog-module-mmnormalize~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mmnormalize-debuginfo", rpm:"rsyslog-module-mmnormalize-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mysql", rpm:"rsyslog-module-mysql~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mysql-debuginfo", rpm:"rsyslog-module-mysql-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-pgsql", rpm:"rsyslog-module-pgsql~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-pgsql-debuginfo", rpm:"rsyslog-module-pgsql-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-relp", rpm:"rsyslog-module-relp~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-relp-debuginfo", rpm:"rsyslog-module-relp-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-snmp", rpm:"rsyslog-module-snmp~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-snmp-debuginfo", rpm:"rsyslog-module-snmp-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-udpspoof", rpm:"rsyslog-module-udpspoof~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-udpspoof-debuginfo", rpm:"rsyslog-module-udpspoof-debuginfo~8.2106.0~8.5.2", rls:"SLES12.0SP5"))) {
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
