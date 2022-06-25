###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_smb_signing_disabled.nasl 11003 2018-08-16 11:08:00Z asteins $
#
# Microsoft SMB Signing Disabled
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.802726");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11003 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-16 13:08:00 +0200 (Thu, 16 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-04-09 18:56:54 +0530 (Mon, 09 Apr 2012)");
  script_name("Microsoft SMB Signing Disabled");
  script_category(ACT_GATHER_INFO);
  script_dependencies("smb_login.nasl");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Checking for SMB signing is disabled.

  The script logs in via smb, checks the SMB Negotiate Protocol response to
  confirm SMB signing is disabled.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("smb_nt.inc");

name = kb_smb_name();
port = kb_smb_transport();

if(!port) port = 139;
if(!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

response = smb_session_request(soc:soc, remote:name);
if(!response)
{
  close(soc);
  exit(0);
}

## SMB Negotiate Protocol Response
## If SMB signing is disabled, then Security Mode: 0x03
prot = smb_neg_prot(soc:soc);
close(soc);

if(prot && ord(prot[39]) == 3){
   log_message(port:port, data:"SMB signing is disabled on this host");
   exit(0);
}

exit(99);