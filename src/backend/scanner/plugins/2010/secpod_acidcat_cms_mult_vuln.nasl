##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_acidcat_cms_mult_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Acidcat CMS Multiple Vulnerabilities
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900750");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2010-0976", "CVE-2010-0984");
  script_name("Acidcat CMS Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38084");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55329");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55331");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10972");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to,

  - 'install.asp' and other 'install_*.asp' scripts which can be accessed
  even after the installation finishes, which might allow remote attackers
  to restart the installation process.

  - improper access restrictions to the 'acidcat_3.mdb' database file in
  the databases directory. An attacker can download the database containing
  credentials via a direct request for databases/acidcat_3.mdb.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Acidcat CMS and is prone to multiple
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to restart
  the installation process and an attacker can download the database containing
  credentials via a direct request for databases/acidcat_3.mdb.");
  script_tag(name:"affected", value:"Acidcat CMS 3.5.3 and prior");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

acidPort = get_http_port(default:80);

if (!can_host_asp(port:acidPort)) exit(0);

foreach dir (make_list_unique("/acidcat", "/Acidcat" ,"/", cgi_dirs(port:acidPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/main_login.asp"), port:acidPort);
  rcvRes = http_keepalive_send_recv(port:acidPort, data:sndReq);

  if(">Acidcat ASP CMS" >< rcvRes)
  {
    ## Send an exploit and receive the response
    sndReq = http_get(item:string(dir, "/install.asp"), port:acidPort);
    rcvRes = http_keepalive_send_recv(port:acidPort, data:sndReq);

    if("Welcome to the Acidcat CMS installation guide" >< rcvRes)
    {
      security_message(port:acidPort);
      exit(0);
    }
  }
}

exit(99);