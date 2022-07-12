###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpdx_35006.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# httpdx Multiple Commands Remote Buffer Overflow Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100210");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_bugtraq_id(35006);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("httpdx Multiple Commands Remote Buffer Overflow Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/httpdx/detected");

  script_tag(name:"summary", value:"The 'httpdx' program is prone to multiple remote buffer-overflow
  vulnerabilities because the application fails to perform adequate
  boundary-checks on user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code
  within the context of the affected application. Failed exploit
  attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"These issues affect httpdx 0.5b. Other versions may also be
  affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35006");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if(!banner || "httpdx" >!< banner)
  exit(0);

if(safe_checks()) {
  if(egrep(pattern:"httpdx 0.5 beta", string: banner)) {
    security_message(port:ftpPort);
    exit(0);
  }
} else {

   soc = open_sock_tcp(ftpPort);
   if(!soc)
     exit(0);

   user = crap(length: 100000);
   pass = "bla";

   ftp_log_in(socket:soc, user:user, pass:pass);
   close(soc);

   sleep(2);

   soc1 = open_sock_tcp(ftpPort);

   if(!soc1){
    security_message(port:ftpPort);
    exit(0);
  }
}

exit(0);