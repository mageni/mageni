###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gtk+2.0 MDKSA-2007:039 (gtk+2.0)
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
tag_insight = "The GdkPixbufLoader function in GIMP ToolKit (GTK+) in GTK 2 (gtk2)
  allows context-dependent attackers to cause a denial of service (crash)
  via a malformed image file. (CVE-2007-0010)

  The version of libgtk+2.0 shipped with Mandriva Linux 2007 fails
  various portions of the lsb-test-desktop test suite, part of LSB 3.1
  certification testing.
  
  The updated packages also address the following issues:
  
  The Home and Desktop entries in the GTK File Chooser are not always
  visible (#26644).
  
  GTK+-based applications (which includes all the Mandriva Linux
  configuration tools, for example) crash (instead of falling back to the
  default theme) when an invalid icon theme is selected. (#27013)
  
  Additional patches from GNOME CVS have been included to address the
  following issues from the GNOME bugzilla:
  
  * 357132 				- fix RGBA colormap issue
  
  * 359537,357280,359052 		- fix various printer bugs
  
  * 357566,353736,357050,363437,379503   - fix various crashes
  
  * 372527				- fix fileselector bug +
  
  potential deadlock";

tag_affected = "gtk+2.0 on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-02/msg00008.php");
  script_oid("1.3.6.1.4.1.25623.1.0.305858");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "MDKSA", value: "2007:039");
  script_cve_id("CVE-2007-0010");
  script_name( "Mandriva Update for gtk+2.0 MDKSA-2007:039 (gtk+2.0)");

  script_tag(name:"summary", value:"Check for the Version of gtk+2.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"gtk+2.0", rpm:"gtk+2.0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0-devel", rpm:"libgdk_pixbuf2.0_0-devel~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgtk+-x11", rpm:"libgtk+-x11~2.0_0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgtk+2.0_0", rpm:"libgtk+2.0_0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgtk+2.0_0-devel", rpm:"libgtk+2.0_0-devel~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0-devel", rpm:"lib64gdk_pixbuf2.0_0-devel~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gtk+-x11", rpm:"lib64gtk+-x11~2.0_0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gtk+2.0_0", rpm:"lib64gtk+2.0_0~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gtk+2.0_0-devel", rpm:"lib64gtk+2.0_0-devel~2.10.3~5.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
