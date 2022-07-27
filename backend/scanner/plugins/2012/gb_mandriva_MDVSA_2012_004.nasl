###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for t1lib MDVSA-2012:004 (t1lib)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:004");
  script_oid("1.3.6.1.4.1.25623.1.0.831524");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-01-13 10:49:44 +0530 (Fri, 13 Jan 2012)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_name("Mandriva Update for t1lib MDVSA-2012:004 (t1lib)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 't1lib'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2|2010\.1)");
  script_tag(name:"affected", value:"t1lib on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in t1lib:
  A heap-based buffer overflow flaw was found in the way AFM font file
  parser, used for rendering of DVI files, in GNOME evince document
  viewer and other products, processed line tokens from the given input
  stream. A remote attacker could provide a DVI file, with embedded
  specially-crafted font file, and trick the local user to open it with
  an application using the AFM font parser, leading to that particular
  application crash or, potentially, arbitrary code execution with the
  privileges of the user running the application. Different vulnerability
  than CVE-2010-2642 (CVE-2011-0433).

  t1lib 5.1.2 and earlier reads from invalid memory locations, which
  allows remote attackers to cause a denial of service (application
  crash) via a crafted Type 1 font in a PDF document, a different
  vulnerability than CVE-2011-0764 (CVE-2011-1552).

  Use-after-free vulnerability in t1lib 5.1.2 and earlier allows
  remote attackers to cause a denial of service (application crash)
  via a PDF document containing a crafted Type 1 font that triggers an
  invalid memory write, a different vulnerability than CVE-2011-0764
  (CVE-2011-1553).

  Off-by-one error in t1lib 5.1.2 and earlier allows remote attackers
  to cause a denial of service (application crash) via a PDF document
  containing a crafted Type 1 font that triggers an invalid memory
  read, integer overflow, and invalid pointer dereference, a different
  vulnerability than CVE-2011-0764 (CVE-2011-1554).

  The updated packages have been patched to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libt1lib5", rpm:"libt1lib5~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libt1lib-devel", rpm:"libt1lib-devel~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libt1lib-static-devel", rpm:"libt1lib-static-devel~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-config", rpm:"t1lib-config~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-progs", rpm:"t1lib-progs~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib5", rpm:"lib64t1lib5~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib-devel", rpm:"lib64t1lib-devel~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib-static-devel", rpm:"lib64t1lib-static-devel~5.1.2~11.2", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"libt1lib5", rpm:"libt1lib5~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libt1lib-devel", rpm:"libt1lib-devel~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libt1lib-static-devel", rpm:"libt1lib-static-devel~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-config", rpm:"t1lib-config~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-progs", rpm:"t1lib-progs~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib5", rpm:"lib64t1lib5~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib-devel", rpm:"lib64t1lib-devel~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib-static-devel", rpm:"lib64t1lib-static-devel~5.1.2~4.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"libt1lib5", rpm:"libt1lib5~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libt1lib-devel", rpm:"libt1lib-devel~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libt1lib-static-devel", rpm:"libt1lib-static-devel~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-config", rpm:"t1lib-config~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"t1lib-progs", rpm:"t1lib-progs~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib5", rpm:"lib64t1lib5~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib-devel", rpm:"lib64t1lib-devel~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64t1lib-static-devel", rpm:"lib64t1lib-static-devel~5.1.2~8.3mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
