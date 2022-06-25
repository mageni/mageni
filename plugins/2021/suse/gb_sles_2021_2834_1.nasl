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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2834.1");
  script_cve_id("CVE-2012-6706", "CVE-2017-12938", "CVE-2017-12940", "CVE-2017-12941", "CVE-2017-12942", "CVE-2017-20006");
  script_tag(name:"creation_date", value:"2021-08-26 02:26:42 +0000 (Thu, 26 Aug 2021)");
  script_version("2021-08-26T02:26:42+0000");
  script_tag(name:"last_modification", value:"2021-08-27 11:22:05 +0000 (Fri, 27 Aug 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2834-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212834-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrar' package(s) announced via the SUSE-SU-2021:2834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unrar to version 5.6.1 fixes several issues.

These security issues were fixed:

CVE-2017-12938: Prevent remote attackers to bypass a directory-traversal
 protection mechanism via vectors involving a symlink to the . directory,
 a symlink to the .. directory, and a regular file (bsc#1054038).

CVE-2017-12940: Prevent out-of-bounds read in the EncodeFileName::Decode
 call within the Archive::ReadHeader15 function (bsc#1054038).

CVE-2017-12941: Prevent an out-of-bounds read in the Unpack::Unpack20
 function (bsc#1054038).

CVE-2017-12942: Prevent a buffer overflow in the Unpack::LongLZ function
 (bsc#1054038).

CVE-2017-20006: Fixed heap-based buffer overflow in Unpack:CopyString
 (bsc#1187974).

These non-security issues were fixed:

Added extraction support for .LZ archives created by Lzip compressor

Enable unpacking of files in ZIP archives compressed with XZ algorithm
 and encrypted with AES

Added support for PAX extended headers inside of TAR archive

If RAR recovery volumes (.rev files) are present in the same folder as
 usual RAR volumes, archive test command verifies .rev contents after
 completing testing .rar files

By default unrar skips symbolic links with absolute paths in link target
 when extracting unless -ola command line switch is specified

Added support for AES-NI CPU instructions

Support for a new RAR 5.0 archiving format

Wildcard exclusion mask for folders

Prevent conditional jumps depending on uninitialised values (bsc#1046882)");

  script_tag(name:"affected", value:"'unrar' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.6.1~4.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.6.1~4.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.6.1~4.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.6.1~4.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.6.1~4.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.6.1~4.5.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.6.1~4.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.6.1~4.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.6.1~4.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"unrar", rpm:"unrar~5.6.1~4.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debuginfo", rpm:"unrar-debuginfo~5.6.1~4.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrar-debugsource", rpm:"unrar-debugsource~5.6.1~4.5.1", rls:"SLES12.0SP5"))) {
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
