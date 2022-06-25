###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_008.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for XFree86-server,xorg-x11-server,xloader SUSE-SA:2007:008
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
tag_insight = "This update fixes three memory corruptions within the X server which
  could be used by local attackers with access to this display to crash
  the X server and potentially execute code.

  CVE-2006-6101: Integer overflow in the ProcRenderAddGlyphs function
  in the Render extension for X.Org 6.8.2, 6.9.0, 7.0,
  and 7.1, and XFree86 X server, allows local users to
  execute arbitrary code via a crafted X protocol request
  that triggers memory corruption during processing of
  glyph management data structures.

  CVE-2006-6102: Integer overflow in the ProcDbeGetVisualInfo function
  in the DBE extension for X.Org 6.8.2, 6.9.0, 7.0,
  and 7.1, and XFree86 X server, allows local users to
  execute arbitrary code via a crafted X protocol request
  that triggers memory corruption during processing of
  unspecified data structures.

  CVE-2006-6103: Integer overflow in the ProcDbeSwapBuffers function in
  the DBE extension for X.Org 6.8.2, 6.9.0, 7.0, and 7.1,
  and XFree86 X server, allows local users to execute
  arbitrary code via a crafted X protocol request
  that triggers memory corruption during processing of
  unspecified data structures.";

tag_impact = "local privilege escalation";
tag_affected = "XFree86-server,xorg-x11-server,xloader on Novell Linux Desktop 9, Novell Linux POS 9, Open Enterprise Server, openSUSE 10.2, SUSE LINUX 10.1, SuSE Linux Enterprise Server 8, SUSE SLED 10, SUSE SLES 10, SUSE SLES 9";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304378");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6101", "CVE-2006-6102", "CVE-2006-6103", "CVE-2006-5867", "CVE-2006-5974");
  script_name( "SuSE Update for XFree86-server,xorg-x11-server,xloader SUSE-SA:2007:008");

  script_tag(name:"summary", value:"Check for the Version of XFree86-server,xorg-x11-server,xloader");
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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.2~30.4", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~6.9.0~50.30", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"xloader", rpm:"xloader~4.2.0~280", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.99.902~43.82", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.0~142", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.99.902~43.82", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.0~142", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.99.902~43.82", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.0~142", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.99.902~43.82", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-server", rpm:"XFree86-server~4.3.0~142", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~6.9.0~50.30", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~6.9.0~50.30", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
