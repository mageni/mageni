###############################################################################
# OpenVAS Vulnerability Test
#
# scan for UPNP hosts
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2005 by John Lampe
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10829");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3723);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0876");
  script_name("scan for UPNP hosts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 by John Lampe");
  script_family("Windows");

  script_xref(name:"URL", value:"http://grc.com/UnPnP/UnPnP.htm");

  script_tag(name:"summary", value:"Microsoft Universal Plug n Play is running on this machine. This service is dangerous for many
  different reasons.");

  script_tag(name:"solution", value:"To disable UPNP see the references.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE); # this check was replaced by gb_upnp_detect.nasl (1.3.6.1.4.1.25623.1.0.103652)

  exit(0);
}

exit(66); # this check was replaced by gb_upnp_detect.nasl (1.3.6.1.4.1.25623.1.0.103652)
