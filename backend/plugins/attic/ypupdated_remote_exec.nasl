###############################################################################
# OpenVAS Vulnerability Test
#
# rpc.ypupdated remote execution
#
# Authors:
# Tenable Network Security and Michel Arboi
#
# Copyright:
# Copyright (C) 2008 Tenable Network Security, Inc. and Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.80036");
  script_version("2020-04-02T11:36:28+0000");
  script_bugtraq_id(1749, 28383);
  script_cve_id("CVE-1999-0208");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_name("rpc.ypupdated remote execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 Tenable Network Security, Inc. and Michel Arboi");
  script_family("RPC");

  script_tag(name:"solution", value:"Remove the '-i' option.
  If this option was not set, the rpc.ypupdated daemon is still vulnerable
  to the old flaw. Contact your vendor for a patch.");

  script_tag(name:"summary", value:"ypupdated with the '-i' option enabled is running on this port.");

  script_tag(name:"insight", value:"ypupdated is part of NIS and allows a client to update NIS maps.

  This old command execution vulnerability was discovered in 1995 and fixed then. However, it is still
  possible to run ypupdated in insecure mode by adding the '-i' option. Anybody can easily run commands
  as root on this machine by specifying an invalid map name that starts with a pipe character. Exploits
  have been publicly available since the first advisory.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # This NVT had called various functions which doesn't exist
