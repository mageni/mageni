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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3767.1");
  script_cve_id("CVE-2022-2795", "CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");
  script_tag(name:"creation_date", value:"2022-10-27 04:38:58 +0000 (Thu, 27 Oct 2022)");
  script_version("2022-10-27T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-10-27 10:11:07 +0000 (Thu, 27 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-23 16:44:00 +0000 (Fri, 23 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3767-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3767-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223767-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2022:3767-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

Update to release 9.16.33:

CVE-2022-2795: Fixed potential performance degredation due to missing
 database lookup limits when processing large delegations (bsc#1203614).

CVE-2022-3080: Fixed assertion failure when there was a stale CNAME in
 the cache for the incoming query and the stale-answer-client-timeout
 option is set to 0 (bsc#1203618).

CVE-2022-38177: Fixed a memory leak that could be externally triggered
 in the DNSSEC verification code for the ECDSA algorithm (bsc#1203619).

CVE-2022-38178: Fixed memory leaks that could be externally triggered in
 the DNSSEC verification code for the EdDSA algorithm (bsc#1203620).

Add systemd drop-in directory for named service (bsc#1201689).

Add modified createNamedConfInclude script and README-bind.chrootenv
 (bsc#1203250).

Feature Changes:
 - Response Rate Limiting (RRL) code now treats all QNAMEs that are
 subject to wildcard processing within a given zone as the same name,
 to prevent circumventing the limits enforced by RRL.

 - Zones using dnssec-policy now require dynamic DNS or inline-signing to
 be configured explicitly.

 - A backward-compatible approach was implemented for encoding
 internationalized domain names (IDN) in dig and converting the domain
 to IDNA2008 form, if that fails, BIND tries an IDNA2003 conversion.

 - The DNSSEC algorithms RSASHA1 and NSEC3RSASHA1 are now automatically
 disabled on systems where they are disallowed by the security policy.
 Primary zones using those algorithms need to be migrated to new
 algorithms prior to running on these systems, as graceful migration to
 different DNSSEC algorithms is not possible when RSASHA1 is disallowed
 by the operating system.

 - Log messages related to fetch limiting have been improved to provide
 more complete information. Specifically, the final counts of allowed
 and spilled fetches are now logged before the counter object is
 destroyed.

 - Non-dynamic zones that inherit dnssec-policy from the view or options
 blocks were not marked as inline-signed and therefore never scheduled
 to be re-signed. This has been fixed.

 - The old max-zone-ttl zone option was meant to be superseded by the
 max-zone-ttl option in dnssec-policy, however, the latter option was
 not fully effective. This has been corrected: zones no longer load if
 they contain TTLs greater than the limit configured in dnssec-policy.
 For zones with both the old max-zone-ttl option and dnssec-policy
 configured, the old option is ignored, and a warning is generated.

 - rndc dumpdb -expired was fixed to include expired RRsets, even if
 stale-cache-enable is set to no and the cache-cleaning time window has
 passed. (jsc#SLE-24600)");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Server Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.33~150400.5.11.1", rls:"SLES15.0SP4"))) {
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
