###############################################################################
# OpenVAS Vulnerability Test
#
# Campsite 'g_campsiteDir' Remote and Local File Inclusion Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900385");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2181", "CVE-2009-2182", "CVE-2009-2183");
  script_bugtraq_id(35456);
  script_name("Campsite 'g_campsiteDir' Remote and Local File Inclusion Vulnerabilities");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8995");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1650");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_campsite_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("campsite/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary local
  files, and cause XSS attack, Directory Traversal attack and remote File
  Injection attack on the affected application.");

  script_tag(name:"affected", value:"Campware, Campsite version 3.3.0 RC1 and prior.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - Input validation errors in the 'admin-files', 'conf/liveuser_configuration.php'
  'include/phorum_load.php', scripts when processing the 'g_campsiteDir' parameter.

  - Input validation error in the 'admin-files/templates/list_dir.php' script
  when, processing the 'listbasedir' parameter.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Campsite version 3.3.6 or later");

  script_tag(name:"summary", value:"This host is running Campsite and is prone to multiple vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

campsitePort = get_http_port(default:80);

campsiteVer = get_kb_item("www/"+ campsitePort + "/Campsite");
if(campsiteVer == NULL){
  exit(0);
}

ver = eregmatch(pattern:"^(.+) under (/.*)$", string:campsiteVer);

if(ver[2] != NULL)
{
  if(!safe_checks())
  {
    sndReq = http_get(item:string(ver[2], 'conf/liveuser_configuration.php' +
                      '?GLOBALS[g_campsiteDir]=[SHELL]'), port:campsitePort);
    rcvRes = http_send_recv(port:campsitePort, data:sndReq);
    if("SHELL" >< rcvRes && "No such file or directory" >< rcvRes)
    {
      security_message(campsitePort);
      exit(0);
    }
  }
}

if(ver[1] != NULL)
{
  if(version_is_less_equal(version:ver[1], test_version:"3.3.0.RC1")){
    security_message(campsitePort);
  }
}
