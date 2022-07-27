###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ardour FEDORA-2010-15560
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "ardour on Fedora 14";
tag_insight = "Ardour is a multichannel hard disk recorder (HDR) and digital audio workstation
  (DAW). It is capable of simultaneous recording 24 or more channels of 32 bit
  audio at 48kHz. Ardour is intended to function as a &quot;professional&quot; HDR system,
  replacing dedicated hardware solutions such as the Mackie HDR, the Tascam 2424
  and more traditional tape systems like the Alesis ADAT series. It is also
  intended to provide the same or better functionality as software systems such
  as ProTools, Samplitude, Logic Audio, Nuendo and Cubase VST (we acknowledge
  these and all other names as trademarks of their respective owners). It
  supports MIDI Machine Control, and so can be controlled from any MMC
  controller, such as the Mackie Digital 8 Bus mixer and many other modern
  digital mixers.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049333.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313116");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-02 08:39:14 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-15560");
  script_cve_id("CVE-2010-3349");
  script_name("Fedora Update for ardour FEDORA-2010-15560");

  script_tag(name: "summary" , value: "Check for the Version of ardour");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"ardour", rpm:"ardour~2.8.11~5.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}