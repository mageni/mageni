###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ghostscript CESA-2012:0095 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018419.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881070");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:00:20 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for ghostscript CESA-2012:0095 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"ghostscript on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Ghostscript is a set of software that provides a PostScript interpreter, a
  set of C procedures (the Ghostscript library, which implements the graphics
  capabilities in the PostScript language) and an interpreter for Portable
  Document Format (PDF) files.

  An integer overflow flaw was found in Ghostscript's TrueType bytecode
  interpreter. An attacker could create a specially-crafted PostScript or PDF
  file that, when interpreted, could cause Ghostscript to crash or,
  potentially, execute arbitrary code. (CVE-2009-3743)

  It was found that Ghostscript always tried to read Ghostscript system
  initialization files from the current working directory before checking
  other directories, even if a search path that did not contain the current
  working directory was specified with the '-I' option, or the '-P-' option
  was used (to prevent the current working directory being searched first).
  If a user ran Ghostscript in an attacker-controlled directory containing a
  system initialization file, it could cause Ghostscript to execute arbitrary
  PostScript code. (CVE-2010-2055)

  Ghostscript included the current working directory in its library search
  path by default. If a user ran Ghostscript without the '-P-' option in an
  attacker-controlled directory containing a specially-crafted PostScript
  library file, it could cause Ghostscript to execute arbitrary PostScript
  code. With this update, Ghostscript no longer searches the current working
  directory for library files by default. (CVE-2010-4820)

  Note: The fix for CVE-2010-4820 could possibly break existing
  configurations. To use the previous, vulnerable behavior, run Ghostscript
  with the '-P' option (to always search the current working directory
  first).

  A flaw was found in the way Ghostscript interpreted PostScript Type 1 and
  PostScript Type 2 font files. An attacker could create a specially-crafted
  PostScript Type 1 or PostScript Type 2 font file that, when interpreted,
  could cause Ghostscript to crash or, potentially, execute arbitrary code.
  (CVE-2010-4054)

  Users of Ghostscript are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.70~11.el6_2.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~8.70~11.el6_2.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.70~11.el6_2.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~8.70~11.el6_2.6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
