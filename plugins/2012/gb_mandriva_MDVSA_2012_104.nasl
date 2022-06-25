###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openjpeg MDVSA-2012:104 (openjpeg)
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:104");
  script_oid("1.3.6.1.4.1.25623.1.0.831698");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-16 11:57:55 +0530 (Mon, 16 Jul 2012)");
  script_cve_id("CVE-2009-5030", "CVE-2012-3358");
  script_name("Mandriva Update for openjpeg MDVSA-2012:104 (openjpeg)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"openjpeg on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in openjpeg:

  OpenJPEG allocated insufficient memory when encoding JPEG 2000 files
  from input images that have certain color depths. A remote attacker
  could provide a specially-crafted image file that, when opened in an
  application linked against OpenJPEG (such as image_to_j2k), would cause
  the application to crash or, potentially, execute arbitrary code with
  the privileges of the user running the application (CVE-2009-5030).

  An input validation flaw, leading to a heap-based buffer overflow,
  was found in the way OpenJPEG handled the tile number and size in an
  image tile header. A remote attacker could provide a specially-crafted
  image file that, when decoded using an application linked against
  OpenJPEG, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application (CVE-2012-3358).

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

  if ((res = isrpmvuln(pkg:"libopenjpeg2", rpm:"libopenjpeg2~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenjpeg-devel", rpm:"libopenjpeg-devel~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openjpeg2", rpm:"lib64openjpeg2~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openjpeg-devel", rpm:"lib64openjpeg-devel~1.3~8.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
