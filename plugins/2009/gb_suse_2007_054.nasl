###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_054.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for XOrg SUSE-SA:2007:054
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The Xorg server was updated to fix 2 problems in the X FontServer found
  in Xorg versions starting with 6.8 and in the Composite extension.

  SUSE Linux 10.0,10.1, openSUSE 10.2, 10.3 and SUSE Linux Enterprise 10
  are affected by these 3 problems, older distributions are not.

  Following issues were fixed:
  IDEF2708 / CVE-2007-4989: X Font Server build_range() Integer Overflow Vulnerability.
  IDEF2709 / CVE-2007-4990: X Font Server swap_char2b() Heap Overflow Vulnerability
  CVE-2007-4730: A buffer overflow in the Composite extension.

  These can be exploited by logged in users to potentially execute code
  in the X server or xfs, which are running as root.";

tag_impact = "local privilege escalation";
tag_affected = "XOrg on SUSE LINUX 10.1, openSUSE 10.2, openSUSE 10.3, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.310915");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-4568", "CVE-2007-4990", "CVE-2007-4730");
  script_name( "SuSE Update for XOrg SUSE-SA:2007:054");

  script_tag(name:"summary", value:"Check for the Version of XOrg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~7.2~135.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.1~91.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~7.2~103.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~7.2~56.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.2~103.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.2~143.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.2~143.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~7.2~143.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel-32bit", rpm:"xorg-x11-devel-32bit~7.2~103.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~7.2~103.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~7.2~28", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.1~33.4", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~7.2~23", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~7.2~10", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~7.2~23", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.2~30.8", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~7.2~30.8", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel-32bit", rpm:"xorg-x11-devel-32bit~7.2~23", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~7.2~23", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-sdk", rpm:"xorg-x11-sdk~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvfb", rpm:"xorg-x11-Xvfb~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel-32bit", rpm:"xorg-x11-devel-32bit~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-100dpi", rpm:"xorg-x11-fonts-100dpi~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-75dpi", rpm:"xorg-x11-fonts-75dpi~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-cyrillic", rpm:"xorg-x11-fonts-cyrillic~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-scalable", rpm:"xorg-x11-fonts-scalable~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-syriac", rpm:"xorg-x11-fonts-syriac~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-man", rpm:"xorg-x11-man~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-glx", rpm:"xorg-x11-server-glx~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xnest", rpm:"xorg-x11-Xnest~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~6.9.0~50.52", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-sdk", rpm:"xorg-x11-sdk~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvfb", rpm:"xorg-x11-Xvfb~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel-32bit", rpm:"xorg-x11-devel-32bit~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-100dpi", rpm:"xorg-x11-fonts-100dpi~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-75dpi", rpm:"xorg-x11-fonts-75dpi~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-cyrillic", rpm:"xorg-x11-fonts-cyrillic~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-scalable", rpm:"xorg-x11-fonts-scalable~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-syriac", rpm:"xorg-x11-fonts-syriac~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs-32bit", rpm:"xorg-x11-libs-32bit~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-man", rpm:"xorg-x11-man~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-glx", rpm:"xorg-x11-server-glx~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xnest", rpm:"xorg-x11-Xnest~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~6.9.0~50.52", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xnest", rpm:"xorg-x11-Xnest~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xprt", rpm:"xorg-x11-Xprt~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvfb", rpm:"xorg-x11-Xvfb~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-driver-options", rpm:"xorg-x11-driver-options~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-100dpi", rpm:"xorg-x11-fonts-100dpi~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-75dpi", rpm:"xorg-x11-fonts-75dpi~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-cyrillic", rpm:"xorg-x11-fonts-cyrillic~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-scalable", rpm:"xorg-x11-fonts-scalable~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-fonts-syriac", rpm:"xorg-x11-fonts-syriac~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-man", rpm:"xorg-x11-man~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-sdk", rpm:"xorg-x11-sdk~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-glx", rpm:"xorg-x11-server-glx~6.9.0~50.52", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
