###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmv_clickheat_unspecified_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# PhpMyVisites ClickHeat Plugin Unspecified Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801202");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-4763");
  script_bugtraq_id(38824);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PhpMyVisites ClickHeat Plugin Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://www.phpmyvisites.us/phpmv2/CHANGELOG");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38824");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Unknown impact and attack vectors.");
  script_tag(name:"affected", value:"PhpMyVisites 2.3 and prior");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error related to the ClickHeat
  plugin used in phpMyVisites.");
  script_tag(name:"summary", value:"This host is running PhpMyVisites and is prone to unspecified
  vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to the latest version of phpMyVisites 2.4 or later, *****
  NOTE : Ignore this warning, if 'ClickHeat' Plugin is not installed or disabled.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://www.phpmyvisites.us/downloads.html");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpmv2", "/phpmyvisites", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('>phpMyVisites' >< res)
  {
    ver = eregmatch(pattern:'"version" content="([0-9\\.]+)"', string:res);

    if(ver[1])
    {
      if(version_is_less(version:ver[1], test_version:"2.4"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);