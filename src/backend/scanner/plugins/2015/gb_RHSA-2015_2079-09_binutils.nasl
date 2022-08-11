###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for binutils RHSA-2015:2079-09
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871504");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:26:23 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502",
                "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for binutils RHSA-2015:2079-09");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The binutils packages provide a set of
binary utilities.

Multiple buffer overflow flaws were found in the libbdf library used by
various binutils utilities. If a user were tricked into processing a
specially crafted file with an application using the libbdf library, it
could cause the application to crash or, potentially, execute arbitrary
code. (CVE-2014-8485, CVE-2014-8501, CVE-2014-8502, CVE-2014-8503,
CVE-2014-8504, CVE-2014-8738)

An integer overflow flaw was found in the libbdf library used by various
binutils utilities. If a user were tricked into processing a specially
crafted file with an application using the libbdf library, it could cause
the application to crash. (CVE-2014-8484)

A directory traversal flaw was found in the strip and objcopy utilities.
A specially crafted file could cause strip or objdump to overwrite an
arbitrary file writable by the user running either of these utilities.
(CVE-2014-8737)

This update fixes the following bugs:

  * Binary files started by the system loader could lack the Relocation
Read-Only (RELRO) protection even though it was explicitly requested when
the application was built. This bug has been fixed on multiple
architectures. Applications and all dependent object files, archives, and
libraries built with an alpha or beta version of binutils should be rebuilt
to correct this defect. (BZ#1200138, BZ#1175624)

  * The ld linker on 64-bit PowerPC now correctly checks the output format
when asked to produce a binary in another format than PowerPC. (BZ#1226864)

  * An important variable that holds the symbol table for the binary being
debugged has been made persistent, and the objdump utility on 64-bit
PowerPC is now able to access the needed information without reading an
invalid memory region. (BZ#1172766)

  * Undesirable runtime relocations described in RHBA-2015:0974. (BZ#872148)

The update adds these enhancements:

  * New hardware instructions of the IBM z Systems z13 are now supported by
assembler, disassembler, and linker, as well as Single Instruction,
Multiple Data (SIMD) instructions. (BZ#1182153)

  * Expressions of the form:'FUNC localentry' to refer to the local entry
point for the FUNC function (if defined) are now supported by the PowerPC
assembler. These are required by the ELFv2 ABI on the little-endian variant
of IBM Power Systems. (BZ#1194164)

All binutils users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"affected", value:"binutils on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00017.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.23.52.0.1~55.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.23.52.0.1~55.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.23.52.0.1~55.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
