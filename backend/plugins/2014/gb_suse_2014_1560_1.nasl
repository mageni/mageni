###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1560_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for clamav openSUSE-SU-2014:1560-1 (clamav)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850622");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-12-06 06:47:37 +0100 (Sat, 06 Dec 2014)");
  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SuSE Update for clamav openSUSE-SU-2014:1560-1 (clamav)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"clamav was updated to version 0.98.5 to fix two security issues.

  These security issues were fixed:

  - Segmentation fault when processing certain files (CVE-2013-6497).

  - Heap-based buffer overflow when scanning crypted PE files
  (CVE-2014-9050).

  The following non-security issues were fixed:

  - Support for the XDP file format and extracting, decoding, and scanning
  PDF files within XDP files.

  - Addition of shared library support for LLVM versions 3.1 - 3.5 for the
  purpose of just-in-time(JIT) compilation of ClamAV bytecode signatures.

  - Enhancements to the clambc command line utility to assist ClamAV
  bytecode signature authors by providing introspection into compiled
  bytecode programs.

  - Resolution of many of the warning messages from ClamAV compilation.

  - Improved detection of malicious PE files.

  - ClamAV 0.98.5 now works with OpenSSL in FIPS compliant mode (bnc#904207).

  - Fix server socket setup code in clamd (bnc#903489).

  - Change updateclamconf to prefer the state of the old config file even
  for commented-out options (bnc#903719).");
  script_tag(name:"affected", value:"clamav on openSUSE 13.1, openSUSE 12.3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.3|openSUSE13\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.3")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.5~5.30.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.98.5~5.30.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.98.5~5.30.3", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.5~22.3", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.98.5~22.3", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.98.5~22.3", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
