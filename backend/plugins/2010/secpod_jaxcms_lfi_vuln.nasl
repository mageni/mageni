###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jaxcms_lfi_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# JaxCMS 'index.php' Local File Inclusion Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
# You should have receivedreceived a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900756");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1043");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("JaxCMS 'index.php' Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38524");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11359");

  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to include
  and execute local files via directory traversal sequences and URL-encoded NULL bytes.");
  script_tag(name:"affected", value:"JaxCMS version 1.0 and prior");
  script_tag(name:"insight", value:"The flaw is due to error in 'index.php' which is not properly
  sanitizing user input passed to the 'p' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running JaxCMS and is prone to local file inclusion
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

jaxPort = get_http_port(default:80);

if(!can_host_php(port:jaxPort)){
  exit(0);
}

foreach dir (make_list_unique("/JaxCMS", "/jaxcms", "/", cgi_dirs(port:jaxPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:jaxPort);

  if("JaxCMS" >< rcvRes)
  {
    ##  Platform independent Attack string
    sndReq = http_get(item:string(dir, "/index.php?p=OpenVAS_LFI%00"), port:jaxPort);
    rcvRes = http_keepalive_send_recv(port:jaxPort, data:sndReq);
    if("failed to open stream" >< rcvRes)
    {
      security_message(port:jaxPort);
      exit(0);
    }
  }
}

exit(99);