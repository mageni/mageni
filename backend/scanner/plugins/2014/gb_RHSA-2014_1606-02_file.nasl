###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for file RHSA-2014:1606-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871263");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-15 06:05:21 +0200 (Wed, 15 Oct 2014)");
  script_cve_id("CVE-2012-1571", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943",
                "CVE-2014-2270", "CVE-2014-3479", "CVE-2014-3480");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for file RHSA-2014:1606-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'file'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The 'file' command is used to identify a particular file according to the
type of data contained in the file. The command can identify various file
types, including ELF binaries, system libraries, RPM packages, and
different graphics formats.

Multiple denial of service flaws were found in the way file parsed certain
Composite Document Format (CDF) files. A remote attacker could use either
of these flaws to crash file, or an application using file, via a specially
crafted CDF file. (CVE-2014-0237, CVE-2014-0238, CVE-2014-3479,
CVE-2014-3480, CVE-2012-1571)

Two denial of service flaws were found in the way file handled indirect and
search rules. A remote attacker could use either of these flaws to cause
file, or an application using file, to crash or consume an excessive amount
of CPU. (CVE-2014-1943, CVE-2014-2270)

This update also fixes the following bugs:

  * Previously, the output of the 'file' command contained redundant white
spaces. With this update, the new STRING_TRIM flag has been introduced to
remove the unnecessary white spaces. (BZ#664513)

  * Due to a bug, the 'file' command could incorrectly identify an XML
document as a LaTex document. The underlying source code has been modified
to fix this bug and the command now works as expected. (BZ#849621)

  * Previously, the 'file' command could not recognize .JPG files and
incorrectly labeled them as 'Minix filesystem'. This bug has been fixed and
the command now properly detects .JPG files. (BZ#873997)

  * Under certain circumstances, the 'file' command incorrectly detected
NETpbm files as 'x86 boot sector'. This update applies a patch to fix this
bug and the command now detects NETpbm files as expected. (BZ#884396)

  * Previously, the 'file' command incorrectly identified ASCII text files as
a .PIC image file. With this update, a patch has been provided to address
this bug and the command now correctly recognizes ASCII text files.
(BZ#980941)

  * On 32-bit PowerPC systems, the 'from' field was missing from the output
of the 'file' command. The underlying source code has been modified to fix
this bug and 'file' output now contains the 'from' field as expected.
(BZ#1037279)

  * The 'file' command incorrectly detected text files as 'RRDTool DB version
ool - Round Robin Database Tool'. This update applies a patch to fix this
bug and the command now correctly detects text files. (BZ#1064463)

  * Previously, the 'file' command supported only version 1 and 2 of the QCOW
format. As a consequence, file was unable to detect a 'qcow2 compat ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"file on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-October/msg00021.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"file", rpm:"file~5.04~21.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-debuginfo", rpm:"file-debuginfo~5.04~21.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-devel", rpm:"file-devel~5.04~21.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.04~21.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.04~21.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
