###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for pulseaudio MDVA-2008:110 (pulseaudio)
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
tag_insight = "The pulseaudio package shipped with Mandriva 2008 Spring does not
  remember a default device setting across sessions. If a user were to
  use pavucontrol to select an alternate default device, it will only
  work for that session. Logging out then back in again will revert
  back to the system default.

  A separate issue also prevents the settings in client.conf from working
  when pulse is started under an X11 session (which is the default way
  of starting pulseaudio). This is because the client.conf has a lower
  priority than the X11 root window properties.
  
  This update addresses both these issues, but please note that
  pulseaudio remembers the per-stream device preferences, so only
  new streams that have not been played before will routed to any
  new default device you pick. This can be remedied by removing the
  ~/.pulse/volume-restore.table file before logging in to a graphical
  session or by moving the individual streams manually in pavucontrol
  as required.";

tag_affected = "pulseaudio on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-07/msg00045.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311847");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVA", value: "2008:110");
  script_name( "Mandriva Update for pulseaudio MDVA-2008:110 (pulseaudio)");

  script_tag(name:"summary", value:"Check for the Version of pulseaudio");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"libpulseaudio0", rpm:"libpulseaudio0~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpulseaudio-devel", rpm:"libpulseaudio-devel~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpulsecore5", rpm:"libpulsecore5~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpulseglib20", rpm:"libpulseglib20~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpulsezeroconf0", rpm:"libpulsezeroconf0~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio", rpm:"pulseaudio~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-esound-compat", rpm:"pulseaudio-esound-compat~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-module-bluetooth", rpm:"pulseaudio-module-bluetooth~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-module-gconf", rpm:"pulseaudio-module-gconf~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-module-jack", rpm:"pulseaudio-module-jack~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-module-lirc", rpm:"pulseaudio-module-lirc~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-module-x11", rpm:"pulseaudio-module-x11~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-module-zeroconf", rpm:"pulseaudio-module-zeroconf~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pulseaudio-utils", rpm:"pulseaudio-utils~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pulseaudio0", rpm:"lib64pulseaudio0~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pulseaudio-devel", rpm:"lib64pulseaudio-devel~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pulsecore5", rpm:"lib64pulsecore5~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pulseglib20", rpm:"lib64pulseglib20~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pulsezeroconf0", rpm:"lib64pulsezeroconf0~0.9.9~7.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
