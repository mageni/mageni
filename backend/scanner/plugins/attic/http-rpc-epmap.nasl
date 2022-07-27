# OpenVAS Vulnerability Test
# Description: Detect the HTTP RPC endpoint mapper
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2005 Alert4Web.com
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10763");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Detect the HTTP RPC endpoint mapper");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("Copyright (C) 2005 Alert4Web.com");
  script_family("Windows");

  script_tag(name:"solution", value:"Deny incoming traffic from the Internet to TCP port 593
  as it may become a security threat in the future, if a
  vulnerability is discovered.

  See the references for more information about CIS.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"summary", value:"This detects the http-rpc-epmap service by connecting
  to the port 593 and processing the buffer received.

  This endpoint mapper provides CIS (COM+ Internet Services)
  parameters like port 135 (epmap) for RPC.");

  script_xref(name:"URL", value:"http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # Broken at this time
