###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_habari_install_path_disc_vuln.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Habari Installation Path Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802320");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Habari Installation Path Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=265");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Habari_Info_Disc_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive
  information like installation path location.");
  script_tag(name:"affected", value:"Habari 0.7.1 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of certain user-supplied
  input passed, which allows attacker to gain sensitive information.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Habari and is prone to path disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list_unique("/habari", "/myhabari", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/", port:port);

  if("<title>My Habari</title>" >< rcvRes)
  {
    sndReq = http_get(item: dir + "/config.php", port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(egrep(pattern:"<b>Fatal error</b>:  Class 'Config' not found in.*\c" +
                     "onfig.php", string:rcvRes))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);