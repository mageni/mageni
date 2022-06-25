###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for sound-scripts MDVA-2008:168 (sound-scripts)
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
tag_insight = "The sound initialization scripts provided with Mandriva Linux 2009
  activate the Analog Loopback channel when it is present. This channel
  is present on most audio chipsets supported by the snd-hda-intel
  driver, which are commonly used on recent systems. When active,
  this channel plays back the sound received by the line-in and mic-in
  channels. If nothing is actually connected to these channels, this
  can result in an unpleasant loud noise over the speakers or headphones
  connected to the line-out or speaker-out connector.

  This update adjusts the sound initialization scripts to mute this
  channel by default. Unfortunately, this change will not be applied
  automatically on already-installed systems, as existing settings
  are automatically stored at shutdown and re-applied at startup on
  Mandriva Linux. If you are suffering from this issue, then you can
  run the command 'reset_sound' as root after installing this update,
  and it should resolve the issue. Alternatively, you can simply disable
  / mute the Analog Loopback channel yourself, using a mixer application.";

tag_affected = "sound-scripts on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-11/msg00005.php");
  script_oid("1.3.6.1.4.1.25623.1.0.309858");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "MDVA", value: "2008:168");
  script_name( "Mandriva Update for sound-scripts MDVA-2008:168 (sound-scripts)");

  script_tag(name:"summary", value:"Check for the Version of sound-scripts");
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

if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"sound-scripts", rpm:"sound-scripts~0.56~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
