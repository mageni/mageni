###############################################################################
# OpenVAS Vulnerability Test
#
# Symantec Anti Virus Corporate Edition Check
#
# Authors:
# Rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2008 Jeff Adams / Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80040");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Symantec Anti Virus Corporate Edition Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Jeff Adams / Tenable Network Security");
  script_family("Product detection");

  script_tag(name:"solution", value:"Make sure SAVCE is installed, running and using the latest
  VDEFS.");

  script_tag(name:"summary", value:"This plugin checks that the remote host has Symantec AntiVirus
  Corporate installed and properly running, and makes sure that the latest Vdefs are loaded.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

##This NVT is deprecated as it produces false positives.
## Moreover it is not referenced by any of the NVTs.
exit(66);
