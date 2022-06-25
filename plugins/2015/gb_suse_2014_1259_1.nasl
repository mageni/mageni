###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1259_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for bash SUSE-SU-2014:1259-1 (bash)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850890");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 13:37:55 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187", "CVE-2014-6271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for bash SUSE-SU-2014:1259-1 (bash)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The command-line shell 'bash' evaluates environment variables, which
  allows the injection of characters and might be used to access files on
  the system in some circumstances (CVE-2014-7169).

  Please note that this issue is different from a previously fixed
  vulnerability tracked under CVE-2014-6271 and it is less serious due to
  the special, non-default system configuration that is needed to create an
  exploitable situation.

  To remove further exploitation potential we now limit the
  function-in-environment variable to variables prefixed with BASH_FUNC_ .
  This hardening feature is work in progress and might be improved in later
  updates.

  Additionally two more security issues were fixed in bash: CVE-2014-7186:
  Nested HERE documents could lead to a crash of bash.

  CVE-2014-7187: Nesting of for loops could lead to a crash of bash.");
  script_tag(name:"affected", value:"bash on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"https://www.suse.com/de-de/security/cve/CVE-2014-7169");
  script_xref(name:"URL", value:"https://www.suse.com/de-de/security/cve/CVE-2014-7187");
  script_xref(name:"URL", value:"https://www.suse.com/de-de/security/cve/CVE-2014-6271");
  script_xref(name:"URL", value:"https://www.suse.com/de-de/security/cve/CVE-2014-7186");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~4.2~75.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreadline6", rpm:"libreadline6~6.2~75.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-doc", rpm:"bash-doc~4.2~75.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-lang", rpm:"bash-lang~4.2~75.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"readline-doc", rpm:"readline-doc~6.2~75.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~4.2~75.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreadline6", rpm:"libreadline6~6.2~75.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-doc", rpm:"bash-doc~4.2~75.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"readline-doc", rpm:"readline-doc~6.2~75.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
